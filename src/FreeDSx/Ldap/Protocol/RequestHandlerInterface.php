<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol;

/**
 * Handles request specific protocol communication details.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface RequestHandlerInterface
{
    public function handleRequest(LdapMessageRequest $message, LdapQueue $queue, array $options) : ?LdapMessageResponse;
}
