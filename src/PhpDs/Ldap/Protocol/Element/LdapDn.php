<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Protocol\Element;

/**
 * Encoded as an Octet String in Asn1.
 *
 * LDAPDN ::= LDAPString -- Constrained to <distinguishedName>
 *                       -- [RFC4514]
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapDn extends LdapString
{
}
