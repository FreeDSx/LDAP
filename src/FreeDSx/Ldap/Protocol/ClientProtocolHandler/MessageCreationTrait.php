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

use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapQueue;

/**
 * Simple methods for constructing the LdapMessage objects in the handlers.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait MessageCreationTrait
{
    protected function makeRequest(LdapQueue $queue, RequestInterface $request, array $controls): LdapMessageRequest
    {
        return new LdapMessageRequest(
            $queue->generateId(),
            $request,
            ...$controls
        );
    }
}
