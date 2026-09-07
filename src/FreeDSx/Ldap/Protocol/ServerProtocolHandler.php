<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ResponseAlreadySentException;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use Throwable;

/**
 * Handles server-client specific protocol interactions.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerProtocolHandler
{
    public function __construct(
        private ServerQueue $queue,
        private MiddlewareHandlerInterface $requestPipeline,
        private SessionEndPolicy $sessionEndPolicy,
        private EventLogger $eventLogger = new EventLogger(null),
        private ResponseFactory $responseFactory = new ResponseFactory(),
        private ConnectionContext $connectionContext = new ConnectionContext(),
    ) {}

    /**
     * Listens for messages from the socket and handles the responses/actions needed.
     *
     * @return ?ConnectionObservation The connection-timeout that ended the session, or null for a normal close.
     *
     * @throws EncoderException
     */
    public function handle(): ?ConnectionObservation
    {
        try {
            return $this->readMessages();
        } catch (Throwable $e) {
            return $this->sessionEndPolicy->end($e);
        } finally {
            if ($this->queue->isConnected()) {
                $this->queue->close();
            }
        }
    }

    /**
     * Used asynchronously to end a client session when the server process is shutting down.
     *
     * @throws EncoderException
     */
    public function shutdown(): void
    {
        $this->sessionEndPolicy->shuttingDown();
        $this->queue->close();
    }

    /**
     * Reads and dispatches messages until the session ends, reporting whatever about the close is worth counting.
     *
     * @throws EncoderException
     */
    private function readMessages(): ?ConnectionObservation
    {
        while (true) {
            try {
                $message = $this->queue->getMessage();
            } catch (MessageDecodeException $e) {
                # The envelope parsed, so this message can be answered by its ID and the session continues. The
                # PDU was consumed before its contents were decoded, so the stream is already past it.
                if ($this->answerDecodeFailure($e)) {
                    continue;
                }

                return $this->sessionEndPolicy->end($e);
            }

            $this->dispatchRequest($message);
            # If a protocol handler closed the TCP connection, then just break here...
            if (!$this->queue->isConnected()) {
                return null;
            }
        }
    }

    /**
     * Runs a single request through the pipeline, answering recoverable failures while keeping the session open.
     *
     * @throws EncoderException
     */
    private function dispatchRequest(LdapMessageRequest $message): void
    {
        try {
            $this->requestPipeline->handle(new ServerRequestContext(
                $message,
                null,
                $this->connectionContext,
            ));
        } catch (ResponseAlreadySentException) {
            # A handler already sent the response (e.g. SASL, which needs the correct multi-round message ID), so
            # there is nothing further to do for this message.
        } catch (OperationException $e) {
            # A pre-pipeline bind/authorization failure. Answer it and keep the session open — a failed bind does not
            # terminate the connection (RFC 4511 §4.2.1). Operation failures are handled by OperationErrorMiddleware.
            #
            # Audited here because these are thrown above the writer, so no middleware sees them.
            $this->eventLogger->recordFailure(
                ServerEvent::OperationRefused,
                $e,
                message: $message,
            );
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
            ));
        }
    }

    /**
     * Answers a decode failure with the response its operation owes, reporting whether one could be framed.
     *
     * @throws EncoderException
     */
    private function answerDecodeFailure(MessageDecodeException $e): bool
    {
        $response = $this->responseFactory->getDecodeFailureResponse(
            $e->getMessageId(),
            $e->getProtocolOpTag(),
            $e->getMessage(),
            $e->getResultCode(),
        );

        // An operation with no response, or a response tag masquerading as a request, leaves nothing to answer with.
        if ($response === null) {
            return false;
        }

        $this->eventLogger->record(
            ServerEvent::MessageDecodeFailed,
            [
                EventContext::REASON_MESSAGE => $e->getMessage(),
                EventContext::REASON_CODE => $e->getResultCode(),
            ],
        );
        $this->queue->sendMessage($response);

        return true;
    }
}
