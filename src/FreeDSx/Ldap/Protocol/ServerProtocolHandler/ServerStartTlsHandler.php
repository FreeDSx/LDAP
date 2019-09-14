<?php
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
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles StartTLS logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerStartTlsHandler implements ServerProtocolHandlerInterface
{
    /**
     * @var bool
     */
    protected static $hasOpenssl;

    public function __construct()
    {
        if (self::$hasOpenssl === null) {
            $this::$hasOpenssl = \extension_loaded('openssl');
        }
    }

    /**
     * {@inheritDoc}
     */
    public function handleRequest(LdapMessageRequest $message, TokenInterface $token, RequestHandlerInterface $dispatcher, ServerQueue $queue, array $options): void
    {
        # If we don't have a SSL cert or the OpenSSL extension is not available, then we can do nothing...
        if (!isset($options['ssl_cert']) || !self::$hasOpenssl) {
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
