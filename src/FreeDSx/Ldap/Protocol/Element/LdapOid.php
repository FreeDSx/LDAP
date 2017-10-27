<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\Element;

use FreeDSx\Ldap\Asn1\Type\OctetStringType;

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
