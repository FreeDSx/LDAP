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
 * This is really an UTF8 string limited to ISO10646. In Asn1 terms it is encoded as an Octet String type.
 *
 * LDAPString ::= OCTET STRING -- UTF-8 encoded,
 *                             -- [ISO10646] characters
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapString extends OctetStringType
{
}
