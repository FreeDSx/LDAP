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
 * OIDs and descriptions for standard LDAP syntaxes (RFC 4517).
 */
final class SyntaxOid
{
    public const OID_DIRECTORY_STRING = '1.3.6.1.4.1.1466.115.121.1.15';

    public const DESC_DIRECTORY_STRING = 'Directory String';

    public const OID_DISTINGUISHED_NAME = '1.3.6.1.4.1.1466.115.121.1.12';

    public const DESC_DISTINGUISHED_NAME = 'DN';

    public const OID_INTEGER = '1.3.6.1.4.1.1466.115.121.1.27';

    public const DESC_INTEGER = 'INTEGER';

    public const OID_BOOLEAN = '1.3.6.1.4.1.1466.115.121.1.7';

    public const DESC_BOOLEAN = 'Boolean';

    public const OID_GENERALIZED_TIME = '1.3.6.1.4.1.1466.115.121.1.24';

    public const DESC_GENERALIZED_TIME = 'Generalized Time';

    public const OID_OCTET_STRING = '1.3.6.1.4.1.1466.115.121.1.40';

    public const DESC_OCTET_STRING = 'Octet String';

    public const OID_TELEPHONE_NUMBER = '1.3.6.1.4.1.1466.115.121.1.50';

    public const DESC_TELEPHONE_NUMBER = 'Telephone Number';

    public const OID_IA5_STRING = '1.3.6.1.4.1.1466.115.121.1.26';

    public const DESC_IA5_STRING = 'IA5 String';

    public const OID_BIT_STRING = '1.3.6.1.4.1.1466.115.121.1.6';

    public const DESC_BIT_STRING = 'Bit String';

    public const OID_NUMERIC_STRING = '1.3.6.1.4.1.1466.115.121.1.36';

    public const DESC_NUMERIC_STRING = 'Numeric String';

    public const OID_OID = '1.3.6.1.4.1.1466.115.121.1.38';

    public const DESC_OID = 'OID';

    public const OID_PRINTABLE_STRING = '1.3.6.1.4.1.1466.115.121.1.44';

    public const DESC_PRINTABLE_STRING = 'Printable String';

    public const OID_POSTAL_ADDRESS = '1.3.6.1.4.1.1466.115.121.1.41';

    public const DESC_POSTAL_ADDRESS = 'Postal Address';

    public const OID_JPEG = '1.3.6.1.4.1.1466.115.121.1.28';

    public const DESC_JPEG = 'JPEG';

    public const OID_ATTRIBUTE_TYPE_DESCRIPTION = '1.3.6.1.4.1.1466.115.121.1.3';

    public const DESC_ATTRIBUTE_TYPE_DESCRIPTION = 'Attribute Type Description';

    public const OID_DIT_CONTENT_RULE_DESCRIPTION = '1.3.6.1.4.1.1466.115.121.1.16';

    public const DESC_DIT_CONTENT_RULE_DESCRIPTION = 'DIT Content Rule Description';

    public const OID_DIT_STRUCTURE_RULE_DESCRIPTION = '1.3.6.1.4.1.1466.115.121.1.17';

    public const DESC_DIT_STRUCTURE_RULE_DESCRIPTION = 'DIT Structure Rule Description';

    public const OID_MATCHING_RULE_DESCRIPTION = '1.3.6.1.4.1.1466.115.121.1.30';

    public const DESC_MATCHING_RULE_DESCRIPTION = 'Matching Rule Description';

    public const OID_MATCHING_RULE_USE_DESCRIPTION = '1.3.6.1.4.1.1466.115.121.1.31';

    public const DESC_MATCHING_RULE_USE_DESCRIPTION = 'Matching Rule Use Description';

    public const OID_NAME_FORM_DESCRIPTION = '1.3.6.1.4.1.1466.115.121.1.35';

    public const DESC_NAME_FORM_DESCRIPTION = 'Name Form Description';

    public const OID_OBJECT_CLASS_DESCRIPTION = '1.3.6.1.4.1.1466.115.121.1.37';

    public const DESC_OBJECT_CLASS_DESCRIPTION = 'Object Class Description';

    public const OID_LDAP_SYNTAX_DESCRIPTION = '1.3.6.1.4.1.1466.115.121.1.54';

    public const DESC_LDAP_SYNTAX_DESCRIPTION = 'LDAP Syntax Description';

    private function __construct() {}
}
