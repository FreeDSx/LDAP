<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Socket\Exception\ConnectionException;

/**
 * Logic for handling an unbind operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientUnbindHandler implements RequestHandlerInterface
{
    use MessageCreationTrait;

    /**
     * @param ClientProtocolContext $context
     * @return null
     * @throws EncoderException
     * @throws ConnectionException
     */
    public function handleRequest(ClientProtocolContext $context): ?LdapMessageResponse
    {
        $queue = $context->getQueue();
        $message = $context->messageToSend();
        $queue->sendMessage($message);
        $queue->close();

        return null;
    }
}
