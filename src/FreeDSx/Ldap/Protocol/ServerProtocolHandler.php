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
use FreeDSx\Socket\Exception\ConnectionException as SocketException;
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
            $this->readMessages();

            return null;
        } catch (Throwable $e) {
            return $this->endSession($e);
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
        try {
            $this->sessionEndPolicy->shuttingDown();
        } finally {
            $this->queue->close();
        }
    }

    /**
     * Used asynchronously to end a client session the server can no longer serve.
     *
     * @throws EncoderException
     */
    public function endAsUnavailable(): void
    {
        try {
            $this->sessionEndPolicy->unavailable();
        } finally {
            $this->queue->close();
        }
    }

    /**
     * Ends the session for a failure or for the socket failing while it ends.
     *
     * @throws EncoderException
     */
    private function endSession(Throwable $failure): ?ConnectionObservation
    {
        try {
            return $this->sessionEndPolicy->end($failure);
        } catch (SocketException $e) {
            # Ending a session for a socket failure writes nothing to the socket.
            return $this->sessionEndPolicy->end($e);
        }
    }

    /**
     * Reads and dispatches messages until the connection is closed or a failure ends the session.
     *
     * @throws EncoderException
     */
    private function readMessages(): void
    {
        while (true) {
            $message = $this->nextMessage();
            if ($message === null) {
                continue;
            }

            $this->dispatchRequest($message);
            # A finished request is released before the wait for the next one.
            unset($message);
            # If a protocol handler closed the TCP connection, then just break here...
            if (!$this->queue->isConnected()) {
                return;
            }
        }
    }

    /**
     * Reads the next request, or null when one that failed to decode was answered instead.
     *
     * @throws MessageDecodeException when the failure cannot be answered.
     */
    private function nextMessage(): ?LdapMessageRequest
    {
        try {
            return $this->queue->getMessage();
        } catch (MessageDecodeException $e) {
            # A message whose envelope parsed is answered by its ID, and the stream is already past it.
            if ($this->decodeFailures->answer($e)) {
                return null;
            }

            throw $e;
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
