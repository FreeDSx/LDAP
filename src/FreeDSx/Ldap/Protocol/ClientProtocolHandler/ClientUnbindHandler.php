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

use FreeDSx\Ldap\Protocol\LdapMessageResponse;

/**
 * Logic for handling an unbind operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientUnbindHandler implements RequestHandlerInterface
{
    use MessageCreationTrait;

    /**
     * {@inheritDoc}
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
