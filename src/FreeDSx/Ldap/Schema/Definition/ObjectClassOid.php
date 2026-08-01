<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Schema\Definition;

/**
 * OIDs, names, and descriptions for standard LDAP object classes (RFC 4519 + RFC 4512).
 *
 * @api
 */
final class ObjectClassOid
{
    public const OID_TOP = '2.5.6.0';

    public const NAME_TOP = 'top';

    public const DESC_TOP = 'top of the class hierarchy';

    public const OID_ALIAS = '2.5.6.1';

    public const NAME_ALIAS = 'alias';

    public const DESC_ALIAS = 'an alias entry pointing at another entry';

    public const OID_PERSON = '2.5.6.6';

    public const NAME_PERSON = 'person';

    public const DESC_PERSON = 'natural persons';

    public const OID_ORGANIZATIONAL_PERSON = '2.5.6.7';

    public const NAME_ORGANIZATIONAL_PERSON = 'organizationalPerson';

    public const DESC_ORGANIZATIONAL_PERSON = 'people associated with an organization';

    public const OID_ORGANIZATIONAL_UNIT = '2.5.6.5';

    public const NAME_ORGANIZATIONAL_UNIT = 'organizationalUnit';

    public const DESC_ORGANIZATIONAL_UNIT = 'organizational units';

    public const OID_ORGANIZATION = '2.5.6.4';

    public const NAME_ORGANIZATION = 'organization';

    public const DESC_ORGANIZATION = 'organizations';

    public const OID_GROUP_OF_NAMES = '2.5.6.9';

    public const NAME_GROUP_OF_NAMES = 'groupOfNames';

    public const DESC_GROUP_OF_NAMES = 'group whose members are distinguished names';

    public const OID_GROUP_OF_UNIQUE_NAMES = '2.5.6.17';

    public const NAME_GROUP_OF_UNIQUE_NAMES = 'groupOfUniqueNames';

    public const DESC_GROUP_OF_UNIQUE_NAMES = 'group whose members are unique distinguished names';

    public const OID_INET_ORG_PERSON = '2.16.840.1.113730.3.2.2';

    public const NAME_INET_ORG_PERSON = 'inetOrgPerson';

    public const DESC_INET_ORG_PERSON = 'internet-enabled person (RFC 2798)';

    public const OID_DOMAIN = '0.9.2342.19200300.100.4.13';

    public const NAME_DOMAIN = 'domain';

    public const DESC_DOMAIN = 'DNS domains';

    public const OID_DC_OBJECT = '1.3.6.1.4.1.1466.344';

    public const NAME_DC_OBJECT = 'dcObject';

    public const DESC_DC_OBJECT = 'auxiliary class for domain component';

    public const OID_SUBSCHEMA = '2.5.20.1';

    public const NAME_SUBSCHEMA = 'subschema';

    public const DESC_SUBSCHEMA = 'server subschema entry';

    public const OID_EXTENSIBLE_OBJECT = '1.3.6.1.4.1.1466.101.120.111';

    public const NAME_EXTENSIBLE_OBJECT = 'extensibleObject';

    public const DESC_EXTENSIBLE_OBJECT = 'any attribute type allowed';

    private function __construct() {}
}
