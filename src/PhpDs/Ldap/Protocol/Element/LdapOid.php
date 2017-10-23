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

use PhpDs\Ldap\Asn1\Type\OctetStringType;

/**
 * This is a UTF8 encoded dotted-decimal representation of an OID. Encoded as an Octet String in Asn1.
 *
 * LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
 *                          -- [RFC4512]
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapOid extends OctetStringType
{
}
