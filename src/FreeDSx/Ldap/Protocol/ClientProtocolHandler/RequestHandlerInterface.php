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
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;

/**
 * Handles request specific protocol communication details.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface RequestHandlerInterface
{
    /**
     * Pass a request to the specific handler and return a response (if applicable).
     */
    public function handleRequest(LdapMessageRequest $message, ClientQueue $queue, array $options) : ?LdapMessageResponse;
}
