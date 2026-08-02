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
 * OIDs and names for standard LDAP matching rules (RFC 4517 + AD extensions).
 *
 * @api
 */
final class MatchingRuleOid
{
    public const OID_OBJECT_IDENTIFIER_MATCH = '2.5.13.0';

    public const NAME_OBJECT_IDENTIFIER_MATCH = 'objectIdentifierMatch';

    public const OID_DISTINGUISHED_NAME_MATCH = '2.5.13.1';

    public const NAME_DISTINGUISHED_NAME_MATCH = 'distinguishedNameMatch';

    public const OID_CASE_IGNORE_MATCH = '2.5.13.2';

    public const NAME_CASE_IGNORE_MATCH = 'caseIgnoreMatch';

    public const OID_CASE_IGNORE_ORDERING_MATCH = '2.5.13.3';

    public const NAME_CASE_IGNORE_ORDERING_MATCH = 'caseIgnoreOrderingMatch';

    public const OID_CASE_IGNORE_SUBSTRINGS_MATCH = '2.5.13.4';

    public const NAME_CASE_IGNORE_SUBSTRINGS_MATCH = 'caseIgnoreSubstringsMatch';

    public const OID_CASE_EXACT_MATCH = '2.5.13.5';

    public const NAME_CASE_EXACT_MATCH = 'caseExactMatch';

    public const OID_CASE_EXACT_ORDERING_MATCH = '2.5.13.6';

    public const NAME_CASE_EXACT_ORDERING_MATCH = 'caseExactOrderingMatch';

    public const OID_CASE_EXACT_SUBSTRINGS_MATCH = '2.5.13.7';

    public const NAME_CASE_EXACT_SUBSTRINGS_MATCH = 'caseExactSubstringsMatch';

    public const OID_NUMERIC_STRING_MATCH = '2.5.13.8';

    public const NAME_NUMERIC_STRING_MATCH = 'numericStringMatch';

    public const OID_NUMERIC_STRING_ORDERING_MATCH = '2.5.13.9';

    public const NAME_NUMERIC_STRING_ORDERING_MATCH = 'numericStringOrderingMatch';

    public const OID_NUMERIC_STRING_SUBSTRINGS_MATCH = '2.5.13.10';

    public const NAME_NUMERIC_STRING_SUBSTRINGS_MATCH = 'numericStringSubstringsMatch';

    public const OID_CASE_IGNORE_LIST_MATCH = '2.5.13.11';

    public const NAME_CASE_IGNORE_LIST_MATCH = 'caseIgnoreListMatch';

    public const OID_CASE_IGNORE_LIST_SUBSTRINGS_MATCH = '2.5.13.12';

    public const NAME_CASE_IGNORE_LIST_SUBSTRINGS_MATCH = 'caseIgnoreListSubstringsMatch';

    public const OID_BOOLEAN_MATCH = '2.5.13.13';

    public const NAME_BOOLEAN_MATCH = 'booleanMatch';

    public const OID_INTEGER_MATCH = '2.5.13.14';

    public const NAME_INTEGER_MATCH = 'integerMatch';

    public const OID_INTEGER_ORDERING_MATCH = '2.5.13.15';

    public const NAME_INTEGER_ORDERING_MATCH = 'integerOrderingMatch';

    public const OID_BIT_STRING_MATCH = '2.5.13.16';

    public const NAME_BIT_STRING_MATCH = 'bitStringMatch';

    public const OID_OCTET_STRING_MATCH = '2.5.13.17';

    public const NAME_OCTET_STRING_MATCH = 'octetStringMatch';

    public const OID_GENERALIZED_TIME_MATCH = '2.5.13.18';

    public const NAME_GENERALIZED_TIME_MATCH = 'generalizedTimeMatch';

    public const OID_GENERALIZED_TIME_ORDERING_MATCH = '2.5.13.19';

    public const NAME_GENERALIZED_TIME_ORDERING_MATCH = 'generalizedTimeOrderingMatch';

    public const OID_TELEPHONE_NUMBER_MATCH = '2.5.13.20';

    public const NAME_TELEPHONE_NUMBER_MATCH = 'telephoneNumberMatch';

    public const OID_TELEPHONE_NUMBER_SUBSTRINGS_MATCH = '2.5.13.21';

    public const NAME_TELEPHONE_NUMBER_SUBSTRINGS_MATCH = 'telephoneNumberSubstringsMatch';

    public const OID_UNIQUE_MEMBER_MATCH = '2.5.13.23';

    public const NAME_UNIQUE_MEMBER_MATCH = 'uniqueMemberMatch';

    public const OID_CASE_EXACT_IA5_MATCH = '1.3.6.1.4.1.1466.109.114.1';

    public const NAME_CASE_EXACT_IA5_MATCH = 'caseExactIA5Match';

    public const OID_CASE_IGNORE_IA5_MATCH = '1.3.6.1.4.1.1466.109.114.2';

    public const NAME_CASE_IGNORE_IA5_MATCH = 'caseIgnoreIA5Match';

    public const OID_CASE_IGNORE_IA5_SUBSTRINGS_MATCH = '1.3.6.1.4.1.1466.109.114.3';

    public const NAME_CASE_IGNORE_IA5_SUBSTRINGS_MATCH = 'caseIgnoreIA5SubstringsMatch';

    public const OID_UUID_MATCH = '1.3.6.1.1.16.2';

    public const NAME_UUID_MATCH = 'uuidMatch';

    public const OID_UUID_ORDERING_MATCH = '1.3.6.1.1.16.3';

    public const NAME_UUID_ORDERING_MATCH = 'uuidOrderingMatch';

    public const OID_BIT_AND_MATCH = '1.2.840.113556.1.4.803';

    public const NAME_BIT_AND_MATCH = 'bitAndMatch';

    public const OID_BIT_OR_MATCH = '1.2.840.113556.1.4.804';

    public const NAME_BIT_OR_MATCH = 'bitOrMatch';

    public const OID_INTEGER_FIRST_COMPONENT_MATCH = '2.5.13.29';

    public const NAME_INTEGER_FIRST_COMPONENT_MATCH = 'integerFirstComponentMatch';

    public const OID_OBJECT_IDENTIFIER_FIRST_COMPONENT_MATCH = '2.5.13.30';

    public const NAME_OBJECT_IDENTIFIER_FIRST_COMPONENT_MATCH = 'objectIdentifierFirstComponentMatch';

    private function __construct() {}
}
