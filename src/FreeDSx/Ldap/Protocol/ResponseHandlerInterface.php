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
 * Handles response specific protocol communication details.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ResponseHandlerInterface
{
    public function handleResponse(LdapMessageRequest $messageTo, LdapMessageResponse $messageFrom, LdapQueue $queue, array $options) :?LdapMessageResponse;
}