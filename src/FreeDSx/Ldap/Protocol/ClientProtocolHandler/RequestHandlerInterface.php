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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;

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
     *
     * @throws UnsolicitedNotificationException
     * @throws OperationException
     */
    public function handleRequest(ClientProtocolContext $context): ?LdapMessageResponse;
}
