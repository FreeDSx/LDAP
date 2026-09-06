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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ConnectionControl;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use Throwable;

use function extension_loaded;

/**
 * Handles StartTLS logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerStartTlsHandler implements ServerProtocolHandlerInterface
{
    private static ?bool $hasOpenssl = null;

    public function __construct(
        private readonly ServerListenerOptionsInterface $options,
        private readonly ConnectionControl $connection,
        private readonly EventLogger $eventLogger = new EventLogger(null),
    ) {
        if (self::$hasOpenssl === null) {
            $this::$hasOpenssl = extension_loaded('openssl');
        }
    }

    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        # RFC 4511 §4.14.2: return unavailable (not protocolError) when the server cannot negotiate TLS.
        if ($this->options->getNetworkConfig()->getSslCert() === null || !self::$hasOpenssl) {
            return $this->failure(
                $message,
                ResultCode::UNAVAILABLE,
                'The server is not configured to provide TLS.',
            );
        }
        # If we are already encrypted, then consider this an operations error...
        if ($this->connection->isEncrypted()) {
            return $this->failure(
                $message,
                ResultCode::OPERATIONS_ERROR,
                'The current LDAP session is already encrypted.',
            );
        }

        # The socket is upgraded in onComplete, after the writer has flushed this SUCCESS in plaintext.
        return ResponseStream::reply(
            $message,
            OperationOutcomeResult::succeeded(),
            new ExtendedResponse(
                new LdapResult(ResultCode::SUCCESS),
                ExtendedRequest::OID_START_TLS,
            ),
        )->withOnComplete(function (ConnectionControl $connection) use ($message): void {
            // Plaintext waiting behind the request is the command-injection shape, so its loss is worth reporting.
            $discarded = $connection->hasBufferedInput();

            try {
                $connection->encrypt();
            } catch (Throwable $e) {
                $this->eventLogger->record(
                    ServerEvent::StartTlsFailed,
                    [EventContext::REASON => $e->getMessage()],
                    message: $message,
                );

                throw $e;
            }

            if ($discarded) {
                $this->eventLogger->record(
                    ServerEvent::StartTlsBufferDiscarded,
                    [EventContext::REASON => 'Plaintext buffered behind the StartTLS request was discarded unread.'],
                    message: $message,
                );
            }

            $this->eventLogger->record(
                ServerEvent::StartTlsSucceeded,
                message: $message,
            );
        });
    }

    private function failure(
        LdapMessageRequest $message,
        int $resultCode,
        string $reason,
    ): ResponseStream {
        $this->eventLogger->record(
            ServerEvent::StartTlsFailed,
            [
                EventContext::RESULT_CODE => $resultCode,
                EventContext::REASON => $reason,
            ],
            message: $message,
        );

        return ResponseStream::reply(
            $message,
            OperationOutcomeResult::failed($resultCode),
            new ExtendedResponse(
                new LdapResult(
                    $resultCode,
                    '',
                    $reason,
                ),
                ExtendedRequest::OID_START_TLS,
            ),
        );
    }
}
