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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Exception\ResponseAlreadySentException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Exception\WriteTimeoutException;
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
        private EventLogger $eventLogger = new EventLogger(null),
        private ResponseFactory $responseFactory = new ResponseFactory(),
        private ConnectionContext $connectionContext = new ConnectionContext(),
    ) {}

    /**
     * Listens for messages from the socket and handles the responses/actions needed.
     *
     * @throws EncoderException
     */
    public function handle(): void
    {
        try {
            while ($message = $this->queue->getMessage()) {
                $this->dispatchRequest($message);
                # If a protocol handler closed the TCP connection, then just break here...
                if (!$this->queue->isConnected()) {
                    break;
                }
            }
        } catch (RequestValidationException $e) {
            # The message ID could not be used (zero or reused). Per RFC 4511 §4.1.1 the server cannot frame a
            # solicited response, so it sends a Notice of Disconnection and terminates the session.
            $this->sendNoticeOfDisconnect($e->getMessage());
        } catch (WriteTimeoutException $e) {
            # The client stopped reading mid-response; nothing further can be sent. Record it and close.
            $this->eventLogger->record(
                ServerEvent::WriteTimeout,
                [EventContext::REASON_MESSAGE => $e->getMessage()],
            );
        } catch (ConnectionException) {
            # Connection closure is recorded by the runner's lifecycle logging; no audit event for normal client disconnects.
        } catch (EncoderException|ProtocolException) {
            # Per RFC 4511 §4.1.1, a PDU that cannot be processed — malformed, or rejected for exceeding the configured
            # size cap (RequestSizeExceededException) — warrants a disconnect with a protocol error. The
            # NoticeOfDisconnectSent event records the specific reason.
            $this->sendNoticeOfDisconnect('The message could not be processed.');
        } catch (Throwable $e) {
            if ($this->queue->isConnected()) {
                $this->sendNoticeOfDisconnect(cause: $e);
            }
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
        $this->sendNoticeOfDisconnect(
            'The server is shutting down.',
            ResultCode::UNAVAILABLE,
        );
        $this->queue->close();
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
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
            ));
        }
    }

    /**
     * @throws EncoderException
     */
    private function sendNoticeOfDisconnect(
        string $message = '',
        int $reasonCode = ResultCode::PROTOCOL_ERROR,
        ?Throwable $cause = null,
    ): void {
        $this->queue->sendMessage($this->responseFactory->getExtendedError(
            $message,
            $reasonCode,
            ExtendedResponse::OID_NOTICE_OF_DISCONNECTION,
        ));
        $this->eventLogger->record(
            ServerEvent::NoticeOfDisconnectSent,
            [
                EventContext::REASON_CODE => $reasonCode,
                EventContext::REASON_MESSAGE => $message,
            ] + $this->eventLogger->exceptionContextFor($cause),
        );
    }
}
