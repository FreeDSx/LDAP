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
use FreeDSx\Ldap\Exception\ConnectionException as LdapConnectionException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RequestSizeExceededException;
use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Exception\IdleTimeoutException;
use FreeDSx\Socket\Exception\WriteTimeoutException;
use Throwable;

/**
 * Decides how a failure that ended the read loop closes the client session.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SessionEndPolicy
{
    public function __construct(
        private DisconnectSender $disconnectSender,
        private EventLogger $eventLogger,
    ) {}

    /**
     * What to report about the close, or null when it is not worth counting.
     *
     * Note: The order is important here.
     *
     * @throws EncoderException
     */
    public function end(Throwable $exception): ?ConnectionObservation
    {
        return match (true) {
            // RFC 4511 §4.1.1: a message ID that is zero or reused cannot frame a solicited response.
            $exception instanceof RequestValidationException => $this->disconnect($exception->getMessage()),
            // The client stopped reading mid-response, so nothing further can be sent.
            $exception instanceof WriteTimeoutException => $this->timedOut(
                ServerEvent::WriteTimeout,
                $exception,
                ConnectionObservation::WriteTimeout,
            ),
            // The client sent nothing within the read timeout, and there is nothing to send back.
            $exception instanceof IdleTimeoutException => $this->timedOut(
                ServerEvent::IdleTimeout,
                $exception,
                ConnectionObservation::IdleTimeout,
            ),
            // An ordinary client disconnect, which the runner's lifecycle logging already records.
            $exception instanceof ConnectionException => null,
            // RFC 4511 §4.1.1, carrying the cause so the log identifies the size violation.
            $exception instanceof RequestSizeExceededException => $this->disconnect(
                $exception->getMessage(),
                cause: $exception,
                closeReason: ConnectionObservation::RequestSizeExceeded,
            ),
            // RFC 4511 §4.1.1: a malformed PDU cannot be processed. The recorded event names the specific reason.
            $exception instanceof EncoderException,
            $exception instanceof ProtocolException => $this->disconnect(
                'The message could not be processed.',
                closeReason: ConnectionObservation::ProtocolError,
            ),
            // RFC 4511 §4.4.1: the connection this session depended on is gone, which no result code can answer.
            $exception instanceof LdapConnectionException => $this->disconnect(
                $exception->getMessage(),
                ResultCode::UNAVAILABLE,
                $exception,
                ConnectionObservation::Unavailable,
            ),
            default => $this->unexpectedFailure($exception),
        };
    }

    /**
     * Ends the session because the server is going away rather than because anything about it failed.
     *
     * @throws EncoderException
     */
    public function shuttingDown(): void
    {
        $this->disconnectSender->send(
            'The server is shutting down.',
            ResultCode::UNAVAILABLE,
        );
    }

    /**
     * @throws EncoderException
     */
    private function disconnect(
        string $message = '',
        int $reasonCode = ResultCode::PROTOCOL_ERROR,
        ?Throwable $cause = null,
        ?ConnectionObservation $closeReason = null,
    ): ?ConnectionObservation {
        $this->disconnectSender->send(
            $message,
            $reasonCode,
            $cause,
        );

        return $closeReason;
    }

    /**
     * A timeout has no answer to send.
     */
    private function timedOut(
        ServerEvent $event,
        Throwable $exception,
        ConnectionObservation $closeReason,
    ): ConnectionObservation {
        $this->eventLogger->record(
            $event,
            [EventContext::REASON_MESSAGE => $exception->getMessage()],
        );

        return $closeReason;
    }

    /**
     * @throws EncoderException
     */
    private function unexpectedFailure(Throwable $exception): null
    {
        $this->disconnectSender->sendIfConnected(cause: $exception);

        return null;
    }
}
