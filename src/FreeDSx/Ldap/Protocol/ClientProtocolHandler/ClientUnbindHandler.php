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

use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\LdapQueue;
use FreeDSx\Ldap\Protocol\RequestHandlerInterface;

/**
 * Logic for handling an unbind operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientUnbindHandler implements RequestHandlerInterface
{
    /**
     * {@inheritDoc}
     */
    public function handleRequest(LdapMessageRequest $message, LdapQueue $queue, array $options): ?LdapMessageResponse
    {
        $queue->sendMessage($message);
        $queue->close();

        return null;
    }
}
