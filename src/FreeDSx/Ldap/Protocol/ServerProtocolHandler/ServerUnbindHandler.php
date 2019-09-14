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

use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles an unbind. Which just closes the connection.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerUnbindHandler implements ServerProtocolHandlerInterface
{
    /**
     * {@inheritDoc}
     */
    public function handleRequest(LdapMessageRequest $message, TokenInterface $token, RequestHandlerInterface $dispatcher, ServerQueue $queue, array $options): void
    {
        $queue->close();
    }
}
