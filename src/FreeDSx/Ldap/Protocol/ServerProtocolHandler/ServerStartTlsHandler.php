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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Exception\ConnectionException;
use function extension_loaded;

/**
 * Handles StartTLS logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerStartTlsHandler implements ServerProtocolHandlerInterface
{
    private static ?bool $hasOpenssl = null;

    public function __construct(private readonly ServerOptions $options)
    {
        if (self::$hasOpenssl === null) {
            $this::$hasOpenssl = extension_loaded('openssl');
        }
    }

    /**
     * {@inheritDoc}
     * @throws ConnectionException
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
        RequestHandlerInterface $dispatcher,
        ServerQueue $queue
    ): void {
        # If we don't have a SSL cert or the OpenSSL extension is not available, then we can do nothing...
        if ($this->options->getSslCert() === null || !self::$hasOpenssl) {
            $queue->sendMessage(new LdapMessageResponse($message->getMessageId(), new ExtendedResponse(
                new LdapResult(ResultCode::PROTOCOL_ERROR),
                ExtendedRequest::OID_START_TLS
            )));

            return;
        }
        # If we are already encrypted, then consider this an operations error...
        if ($queue->isEncrypted()) {
            $queue->sendMessage(new LdapMessageResponse($message->getMessageId(), new ExtendedResponse(
                new LdapResult(ResultCode::OPERATIONS_ERROR, '', 'The current LDAP session is already encrypted.'),
                ExtendedRequest::OID_START_TLS
            )));

            return;
        }

        $queue->sendMessage(new LdapMessageResponse($message->getMessageId(), new ExtendedResponse(
            new LdapResult(ResultCode::SUCCESS),
            ExtendedRequest::OID_START_TLS
        )));
        $queue->encrypt();
    }
}
