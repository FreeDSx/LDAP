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
use FreeDSx\Ldap\Exception\AnswerableExceptionInterface;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ResponseAlreadySentException;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\FailureAnswerTrait;
use Throwable;

/**
 * Handles server-client specific protocol interactions.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerProtocolHandler
{
    use FailureAnswerTrait;

    public function __construct(
        private ServerQueue $queue,
        private MiddlewareHandlerInterface $requestPipeline,
        private SessionEndPolicy $sessionEndPolicy,
        private DecodeFailureResponder $decodeFailures,
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
     * Used asynchronously to end a client session the server can no longer serve.
     *
     * @throws EncoderException
     */
    public function endAsUnavailable(): void
    {
        $this->sessionEndPolicy->unavailable();
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
                if ($this->decodeFailures->answer($e)) {
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
        } catch (AnswerableExceptionInterface $e) {
            # No middleware sees a failure thrown above the writer; a failed bind keeps the session (RFC 4511 4.2.1).
            $failure = $this->answerFor($e) ?? throw $e;

            $this->eventLogger->recordFailure(
                ServerEvent::OperationRefused,
                $failure,
                message: $message,
                cause: $failure->getPrevious(),
            );
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $failure->getCode(),
                $failure->getMessage(),
                null,
                [],
                ...$failure->controls()->toArray(),
            ));
        }
    }
}
