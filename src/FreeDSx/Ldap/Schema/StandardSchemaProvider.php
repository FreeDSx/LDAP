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

namespace FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Definition\LdapSyntax;
use FreeDSx\Ldap\Schema\Definition\MatchingRule;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Matching\BitMaskComparator;
use FreeDSx\Ldap\Schema\Matching\BooleanComparator;
use FreeDSx\Ldap\Schema\Matching\CaseExactComparator;
use FreeDSx\Ldap\Schema\Matching\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\CaseIgnoreIa5Comparator;
use FreeDSx\Ldap\Schema\Matching\DistinguishedNameComparator;
use FreeDSx\Ldap\Schema\Matching\GeneralizedTimeComparator;
use FreeDSx\Ldap\Schema\Matching\IntegerComparator;
use FreeDSx\Ldap\Schema\Matching\OctetStringComparator;
use FreeDSx\Ldap\Schema\Matching\TelephoneNumberComparator;

/**
 * Builds the core Schema with RFC 4517/4519/4512 standard definitions.
 */
final class StandardSchemaProvider
{
    private function __construct() {}

    public static function buildCore(): Schema
    {
        $schema = new Schema();

        foreach (self::syntaxes() as $syntax) {
            $schema->addSyntax($syntax);
        }
        foreach (self::matchingRules() as $rule) {
            $schema->addMatchingRule($rule);
        }
        foreach (self::attributeTypes() as $type) {
            $schema->addAttributeType($type);
        }
        foreach (self::objectClasses() as $class) {
            $schema->addObjectClass($class);
        }

        return $schema;
    }

    /**
     * @return list<LdapSyntax>
     */
    private static function syntaxes(): array
    {
        return [
            new LdapSyntax(SyntaxOid::OID_DIRECTORY_STRING, SyntaxOid::DESC_DIRECTORY_STRING),
            new LdapSyntax(SyntaxOid::OID_DISTINGUISHED_NAME, SyntaxOid::DESC_DISTINGUISHED_NAME),
            new LdapSyntax(SyntaxOid::OID_INTEGER, SyntaxOid::DESC_INTEGER),
            new LdapSyntax(SyntaxOid::OID_BOOLEAN, SyntaxOid::DESC_BOOLEAN),
            new LdapSyntax(SyntaxOid::OID_GENERALIZED_TIME, SyntaxOid::DESC_GENERALIZED_TIME),
            new LdapSyntax(SyntaxOid::OID_OCTET_STRING, SyntaxOid::DESC_OCTET_STRING),
            new LdapSyntax(SyntaxOid::OID_TELEPHONE_NUMBER, SyntaxOid::DESC_TELEPHONE_NUMBER),
            new LdapSyntax(SyntaxOid::OID_IA5_STRING, SyntaxOid::DESC_IA5_STRING),
            new LdapSyntax(SyntaxOid::OID_BIT_STRING, SyntaxOid::DESC_BIT_STRING),
            new LdapSyntax(SyntaxOid::OID_NUMERIC_STRING, SyntaxOid::DESC_NUMERIC_STRING),
            new LdapSyntax(SyntaxOid::OID_OID, SyntaxOid::DESC_OID),
            new LdapSyntax(SyntaxOid::OID_PRINTABLE_STRING, SyntaxOid::DESC_PRINTABLE_STRING),
            new LdapSyntax(SyntaxOid::OID_POSTAL_ADDRESS, SyntaxOid::DESC_POSTAL_ADDRESS),
            new LdapSyntax(SyntaxOid::OID_JPEG, SyntaxOid::DESC_JPEG),
        ];
    }

    /**
     * @return list<MatchingRule>
     */
    private static function matchingRules(): array
    {
        $caseIgnore = new CaseIgnoreComparator();
        $caseExact = new CaseExactComparator();
        $integer = new IntegerComparator();
        $generalizedTime = new GeneralizedTimeComparator();

        return [
            new MatchingRule(
                MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH,
                [MatchingRuleOid::NAME_DISTINGUISHED_NAME_MATCH],
                SyntaxOid::OID_DISTINGUISHED_NAME,
                new DistinguishedNameComparator(),
            ),
            new MatchingRule(
                MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                [MatchingRuleOid::NAME_CASE_IGNORE_MATCH],
                SyntaxOid::OID_DIRECTORY_STRING,
                $caseIgnore,
            ),
            new MatchingRule(
                MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH,
                [MatchingRuleOid::NAME_CASE_IGNORE_ORDERING_MATCH],
                SyntaxOid::OID_DIRECTORY_STRING,
                $caseIgnore,
            ),
            new MatchingRule(
                MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                [MatchingRuleOid::NAME_CASE_IGNORE_SUBSTRINGS_MATCH],
                SyntaxOid::OID_DIRECTORY_STRING,
                $caseIgnore,
            ),
            new MatchingRule(
                MatchingRuleOid::OID_CASE_EXACT_MATCH,
                [MatchingRuleOid::NAME_CASE_EXACT_MATCH],
                SyntaxOid::OID_DIRECTORY_STRING,
                $caseExact,
            ),
            new MatchingRule(
                MatchingRuleOid::OID_CASE_EXACT_ORDERING_MATCH,
                [MatchingRuleOid::NAME_CASE_EXACT_ORDERING_MATCH],
                SyntaxOid::OID_DIRECTORY_STRING,
                $caseExact,
            ),
            new MatchingRule(
                MatchingRuleOid::OID_CASE_EXACT_SUBSTRINGS_MATCH,
                [MatchingRuleOid::NAME_CASE_EXACT_SUBSTRINGS_MATCH],
                SyntaxOid::OID_DIRECTORY_STRING,
                $caseExact,
            ),
            new MatchingRule(
                MatchingRuleOid::OID_BOOLEAN_MATCH,
                [MatchingRuleOid::NAME_BOOLEAN_MATCH],
                SyntaxOid::OID_BOOLEAN,
                new BooleanComparator(),
            ),
            new MatchingRule(
                MatchingRuleOid::OID_INTEGER_MATCH,
                [MatchingRuleOid::NAME_INTEGER_MATCH],
                SyntaxOid::OID_INTEGER,
                $integer,
            ),
            new MatchingRule(
                MatchingRuleOid::OID_INTEGER_ORDERING_MATCH,
                [MatchingRuleOid::NAME_INTEGER_ORDERING_MATCH],
                SyntaxOid::OID_INTEGER,
                $integer,
            ),
            new MatchingRule(
                MatchingRuleOid::OID_OCTET_STRING_MATCH,
                [MatchingRuleOid::NAME_OCTET_STRING_MATCH],
                SyntaxOid::OID_OCTET_STRING,
                new OctetStringComparator(),
            ),
            new MatchingRule(
                MatchingRuleOid::OID_GENERALIZED_TIME_MATCH,
                [MatchingRuleOid::NAME_GENERALIZED_TIME_MATCH],
                SyntaxOid::OID_GENERALIZED_TIME,
                $generalizedTime,
            ),
            new MatchingRule(
                MatchingRuleOid::OID_GENERALIZED_TIME_ORDERING_MATCH,
                [MatchingRuleOid::NAME_GENERALIZED_TIME_ORDERING_MATCH],
                SyntaxOid::OID_GENERALIZED_TIME,
                $generalizedTime,
            ),
            new MatchingRule(
                MatchingRuleOid::OID_TELEPHONE_NUMBER_MATCH,
                [MatchingRuleOid::NAME_TELEPHONE_NUMBER_MATCH],
                SyntaxOid::OID_TELEPHONE_NUMBER,
                new TelephoneNumberComparator(),
            ),
            new MatchingRule(
                MatchingRuleOid::OID_CASE_EXACT_IA5_MATCH,
                [MatchingRuleOid::NAME_CASE_EXACT_IA5_MATCH],
                SyntaxOid::OID_IA5_STRING,
                $caseExact,
            ),
            new MatchingRule(
                MatchingRuleOid::OID_CASE_IGNORE_IA5_MATCH,
                [MatchingRuleOid::NAME_CASE_IGNORE_IA5_MATCH],
                SyntaxOid::OID_IA5_STRING,
                new CaseIgnoreIa5Comparator(),
            ),
            new MatchingRule(
                MatchingRuleOid::OID_BIT_AND_MATCH,
                [MatchingRuleOid::NAME_BIT_AND_MATCH],
                SyntaxOid::OID_INTEGER,
                new BitMaskComparator(requireAllBits: true),
            ),
            new MatchingRule(
                MatchingRuleOid::OID_BIT_OR_MATCH,
                [MatchingRuleOid::NAME_BIT_OR_MATCH],
                SyntaxOid::OID_INTEGER,
                new BitMaskComparator(requireAllBits: false),
            ),
        ];
    }

    /**
     * @return list<AttributeType>
     */
    private static function attributeTypes(): array
    {
        return [
            ...self::userAttributeTypes(),
            ...self::operationalAttributeTypes(),
        ];
    }

    /**
     * @return list<AttributeType>
     */
    private static function userAttributeTypes(): array
    {
        return [
            new AttributeType(
                AttributeTypeOid::OID_OBJECT_CLASS,
                [AttributeTypeOid::NAME_OBJECT_CLASS],
                equalityOid: MatchingRuleOid::OID_OBJECT_IDENTIFIER_MATCH,
                syntaxOid: SyntaxOid::OID_OID,
                desc: AttributeTypeOid::DESC_OBJECT_CLASS,
            ),
            new AttributeType(
                AttributeTypeOid::OID_ALIASED_OBJECT_NAME,
                [AttributeTypeOid::NAME_ALIASED_OBJECT_NAME, AttributeTypeOid::ALIAS_ALIASED_OBJECT_NAME],
                equalityOid: MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH,
                syntaxOid: SyntaxOid::OID_DISTINGUISHED_NAME,
                singleValue: true,
                desc: AttributeTypeOid::DESC_ALIASED_OBJECT_NAME,
            ),
            new AttributeType(
                AttributeTypeOid::OID_NAME,
                [AttributeTypeOid::NAME_NAME],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                orderingOid: MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                desc: AttributeTypeOid::DESC_NAME,
            ),
            new AttributeType(
                AttributeTypeOid::OID_CN,
                [AttributeTypeOid::NAME_CN, AttributeTypeOid::ALIAS_CN],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                orderingOid: MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                superTypeOid: AttributeTypeOid::OID_NAME,
                desc: AttributeTypeOid::DESC_CN,
            ),
            new AttributeType(
                AttributeTypeOid::OID_SN,
                [AttributeTypeOid::NAME_SN, AttributeTypeOid::ALIAS_SN],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                orderingOid: MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                superTypeOid: AttributeTypeOid::OID_NAME,
                desc: AttributeTypeOid::DESC_SN,
            ),
            new AttributeType(
                AttributeTypeOid::OID_GIVEN_NAME,
                [AttributeTypeOid::NAME_GIVEN_NAME],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                orderingOid: MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                superTypeOid: AttributeTypeOid::OID_NAME,
                desc: AttributeTypeOid::DESC_GIVEN_NAME,
            ),
            new AttributeType(
                AttributeTypeOid::OID_INITIALS,
                [AttributeTypeOid::NAME_INITIALS],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                superTypeOid: AttributeTypeOid::OID_NAME,
                desc: AttributeTypeOid::DESC_INITIALS,
            ),
            new AttributeType(
                AttributeTypeOid::OID_UID,
                [AttributeTypeOid::NAME_UID, AttributeTypeOid::ALIAS_UID],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                desc: AttributeTypeOid::DESC_UID,
            ),
            new AttributeType(
                AttributeTypeOid::OID_MAIL,
                [AttributeTypeOid::NAME_MAIL, AttributeTypeOid::ALIAS_MAIL],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_IA5_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_IA5_STRING,
                desc: AttributeTypeOid::DESC_MAIL,
            ),
            new AttributeType(
                AttributeTypeOid::OID_USER_PASSWORD,
                [AttributeTypeOid::NAME_USER_PASSWORD],
                equalityOid: MatchingRuleOid::OID_OCTET_STRING_MATCH,
                syntaxOid: SyntaxOid::OID_OCTET_STRING,
                desc: AttributeTypeOid::DESC_USER_PASSWORD,
                // Write-only to an ordinary client: settable, but never readable back through a result or a filter.
                extensions: [
                    AttributeType::EXTENSION_CONFIDENTIAL => [AttributeType::EXTENSION_ENABLED_VALUE],
                ],
            ),
            new AttributeType(
                AttributeTypeOid::OID_MEMBER,
                [AttributeTypeOid::NAME_MEMBER],
                equalityOid: MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH,
                syntaxOid: SyntaxOid::OID_DISTINGUISHED_NAME,
                desc: AttributeTypeOid::DESC_MEMBER,
            ),
            new AttributeType(
                AttributeTypeOid::OID_UNIQUE_MEMBER,
                [AttributeTypeOid::NAME_UNIQUE_MEMBER],
                equalityOid: MatchingRuleOid::OID_UNIQUE_MEMBER_MATCH,
                syntaxOid: SyntaxOid::OID_DISTINGUISHED_NAME,
                desc: AttributeTypeOid::DESC_UNIQUE_MEMBER,
            ),
            new AttributeType(
                AttributeTypeOid::OID_O,
                [AttributeTypeOid::NAME_O, AttributeTypeOid::ALIAS_O],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                orderingOid: MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                desc: AttributeTypeOid::DESC_O,
            ),
            new AttributeType(
                AttributeTypeOid::OID_OU,
                [AttributeTypeOid::NAME_OU, AttributeTypeOid::ALIAS_OU],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                orderingOid: MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                desc: AttributeTypeOid::DESC_OU,
            ),
            new AttributeType(
                AttributeTypeOid::OID_TITLE,
                [AttributeTypeOid::NAME_TITLE],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                orderingOid: MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                desc: AttributeTypeOid::DESC_TITLE,
            ),
            new AttributeType(
                AttributeTypeOid::OID_DESCRIPTION,
                [AttributeTypeOid::NAME_DESCRIPTION],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                desc: AttributeTypeOid::DESC_DESCRIPTION,
            ),
            new AttributeType(
                AttributeTypeOid::OID_SEE_ALSO,
                [AttributeTypeOid::NAME_SEE_ALSO],
                equalityOid: MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH,
                syntaxOid: SyntaxOid::OID_DISTINGUISHED_NAME,
                desc: AttributeTypeOid::DESC_SEE_ALSO,
            ),
            new AttributeType(
                AttributeTypeOid::OID_TELEPHONE_NUMBER,
                [AttributeTypeOid::NAME_TELEPHONE_NUMBER],
                equalityOid: MatchingRuleOid::OID_TELEPHONE_NUMBER_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_TELEPHONE_NUMBER,
                desc: AttributeTypeOid::DESC_TELEPHONE_NUMBER,
            ),
            new AttributeType(
                AttributeTypeOid::OID_C,
                [AttributeTypeOid::NAME_C, AttributeTypeOid::ALIAS_C],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_PRINTABLE_STRING,
                singleValue: true,
                desc: AttributeTypeOid::DESC_C,
            ),
            new AttributeType(
                AttributeTypeOid::OID_L,
                [AttributeTypeOid::NAME_L, AttributeTypeOid::ALIAS_L],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                orderingOid: MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                desc: AttributeTypeOid::DESC_L,
            ),
            new AttributeType(
                AttributeTypeOid::OID_ST,
                [AttributeTypeOid::NAME_ST, AttributeTypeOid::ALIAS_ST],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                orderingOid: MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                desc: AttributeTypeOid::DESC_ST,
            ),
            new AttributeType(
                AttributeTypeOid::OID_STREET,
                [AttributeTypeOid::NAME_STREET, AttributeTypeOid::ALIAS_STREET],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                desc: AttributeTypeOid::DESC_STREET,
            ),
            new AttributeType(
                AttributeTypeOid::OID_POSTAL_CODE,
                [AttributeTypeOid::NAME_POSTAL_CODE],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                desc: AttributeTypeOid::DESC_POSTAL_CODE,
            ),
            new AttributeType(
                AttributeTypeOid::OID_DC,
                [AttributeTypeOid::NAME_DC, AttributeTypeOid::ALIAS_DC],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_IA5_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_IA5_STRING,
                singleValue: true,
                desc: AttributeTypeOid::DESC_DC,
            ),
            new AttributeType(
                AttributeTypeOid::OID_DISPLAY_NAME,
                [AttributeTypeOid::NAME_DISPLAY_NAME],
                equalityOid: MatchingRuleOid::OID_CASE_IGNORE_MATCH,
                substringOid: MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                singleValue: true,
                desc: AttributeTypeOid::DESC_DISPLAY_NAME,
            ),
            new AttributeType(
                AttributeTypeOid::OID_EMPLOYEE_NUMBER,
                [AttributeTypeOid::NAME_EMPLOYEE_NUMBER],
                equalityOid: MatchingRuleOid::OID_CASE_EXACT_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                singleValue: true,
                desc: AttributeTypeOid::DESC_EMPLOYEE_NUMBER,
            ),
            new AttributeType(
                AttributeTypeOid::OID_MEMBER_OF,
                [AttributeTypeOid::NAME_MEMBER_OF],
                equalityOid: MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH,
                syntaxOid: SyntaxOid::OID_DISTINGUISHED_NAME,
                desc: AttributeTypeOid::DESC_MEMBER_OF,
            ),
            new AttributeType(
                AttributeTypeOid::OID_LABELED_URI,
                [AttributeTypeOid::NAME_LABELED_URI],
                equalityOid: MatchingRuleOid::OID_CASE_EXACT_MATCH,
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                desc: AttributeTypeOid::DESC_LABELED_URI,
            ),
            new AttributeType(
                AttributeTypeOid::OID_JPEG_PHOTO,
                [AttributeTypeOid::NAME_JPEG_PHOTO],
                syntaxOid: SyntaxOid::OID_JPEG,
                desc: AttributeTypeOid::DESC_JPEG_PHOTO,
            ),
        ];
    }

    /**
     * @return list<AttributeType>
     */
    private static function operationalAttributeTypes(): array
    {
        return [
            new AttributeType(
                AttributeTypeOid::OID_CREATE_TIMESTAMP,
                [AttributeTypeOid::NAME_CREATE_TIMESTAMP],
                equalityOid: MatchingRuleOid::OID_GENERALIZED_TIME_MATCH,
                orderingOid: MatchingRuleOid::OID_GENERALIZED_TIME_ORDERING_MATCH,
                syntaxOid: SyntaxOid::OID_GENERALIZED_TIME,
                singleValue: true,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: AttributeTypeOid::DESC_CREATE_TIMESTAMP,
            ),
            new AttributeType(
                AttributeTypeOid::OID_MODIFY_TIMESTAMP,
                [AttributeTypeOid::NAME_MODIFY_TIMESTAMP],
                equalityOid: MatchingRuleOid::OID_GENERALIZED_TIME_MATCH,
                orderingOid: MatchingRuleOid::OID_GENERALIZED_TIME_ORDERING_MATCH,
                syntaxOid: SyntaxOid::OID_GENERALIZED_TIME,
                singleValue: true,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: AttributeTypeOid::DESC_MODIFY_TIMESTAMP,
            ),
            new AttributeType(
                AttributeTypeOid::OID_CREATORS_NAME,
                [AttributeTypeOid::NAME_CREATORS_NAME],
                equalityOid: MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH,
                syntaxOid: SyntaxOid::OID_DISTINGUISHED_NAME,
                singleValue: true,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: AttributeTypeOid::DESC_CREATORS_NAME,
            ),
            new AttributeType(
                AttributeTypeOid::OID_MODIFIERS_NAME,
                [AttributeTypeOid::NAME_MODIFIERS_NAME],
                equalityOid: MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH,
                syntaxOid: SyntaxOid::OID_DISTINGUISHED_NAME,
                singleValue: true,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: AttributeTypeOid::DESC_MODIFIERS_NAME,
            ),
            new AttributeType(
                AttributeTypeOid::OID_SUBSCHEMA_SUBENTRY,
                [AttributeTypeOid::NAME_SUBSCHEMA_SUBENTRY],
                equalityOid: MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH,
                syntaxOid: SyntaxOid::OID_DISTINGUISHED_NAME,
                singleValue: true,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: AttributeTypeOid::DESC_SUBSCHEMA_SUBENTRY,
            ),
            new AttributeType(
                AttributeTypeOid::OID_HAS_SUBORDINATES,
                [AttributeTypeOid::NAME_HAS_SUBORDINATES],
                equalityOid: MatchingRuleOid::OID_BOOLEAN_MATCH,
                syntaxOid: SyntaxOid::OID_BOOLEAN,
                singleValue: true,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: AttributeTypeOid::DESC_HAS_SUBORDINATES,
            ),
            new AttributeType(
                AttributeTypeOid::OID_STRUCTURAL_OBJECT_CLASS,
                [AttributeTypeOid::NAME_STRUCTURAL_OBJECT_CLASS],
                equalityOid: MatchingRuleOid::OID_OBJECT_IDENTIFIER_MATCH,
                syntaxOid: SyntaxOid::OID_OID,
                singleValue: true,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: AttributeTypeOid::DESC_STRUCTURAL_OBJECT_CLASS,
            ),
            new AttributeType(
                AttributeTypeOid::OID_ENTRY_UUID,
                [AttributeTypeOid::NAME_ENTRY_UUID],
                equalityOid: MatchingRuleOid::OID_OCTET_STRING_MATCH,
                syntaxOid: SyntaxOid::OID_OCTET_STRING,
                singleValue: true,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: AttributeTypeOid::DESC_ENTRY_UUID,
            ),
            new AttributeType(
                AttributeTypeOid::OID_ENTRY_DN,
                [AttributeTypeOid::NAME_ENTRY_DN],
                equalityOid: MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH,
                syntaxOid: SyntaxOid::OID_DISTINGUISHED_NAME,
                singleValue: true,
                noUserModification: true,
                usage: AttributeUsage::DirectoryOperation,
                desc: AttributeTypeOid::DESC_ENTRY_DN,
            ),
        ];
    }

    /**
     * @return list<ObjectClass>
     */
    private static function objectClasses(): array
    {
        return [
            new ObjectClass(
                ObjectClassOid::OID_TOP,
                [ObjectClassOid::NAME_TOP],
                type: ObjectClassType::AbstractClass,
                must: [AttributeTypeOid::NAME_OBJECT_CLASS],
                desc: ObjectClassOid::DESC_TOP,
            ),
            new ObjectClass(
                ObjectClassOid::OID_ALIAS,
                [ObjectClassOid::NAME_ALIAS],
                type: ObjectClassType::StructuralClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                must: [AttributeTypeOid::NAME_ALIASED_OBJECT_NAME],
                desc: ObjectClassOid::DESC_ALIAS,
            ),
            new ObjectClass(
                ObjectClassOid::OID_PERSON,
                [ObjectClassOid::NAME_PERSON],
                type: ObjectClassType::StructuralClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                must: [AttributeTypeOid::NAME_SN, AttributeTypeOid::NAME_CN],
                may: [
                    AttributeTypeOid::NAME_USER_PASSWORD,
                    AttributeTypeOid::NAME_TELEPHONE_NUMBER,
                    AttributeTypeOid::NAME_SEE_ALSO,
                    AttributeTypeOid::NAME_DESCRIPTION,
                ],
                desc: ObjectClassOid::DESC_PERSON,
            ),
            new ObjectClass(
                ObjectClassOid::OID_ORGANIZATIONAL_PERSON,
                [ObjectClassOid::NAME_ORGANIZATIONAL_PERSON],
                type: ObjectClassType::StructuralClass,
                superClassOids: [ObjectClassOid::OID_PERSON],
                may: [
                    AttributeTypeOid::NAME_TITLE,
                    AttributeTypeOid::NAME_ST,
                    AttributeTypeOid::NAME_L,
                    AttributeTypeOid::NAME_C,
                    AttributeTypeOid::NAME_STREET,
                    AttributeTypeOid::NAME_POSTAL_CODE,
                    AttributeTypeOid::NAME_OU,
                    AttributeTypeOid::NAME_TELEPHONE_NUMBER,
                ],
                desc: ObjectClassOid::DESC_ORGANIZATIONAL_PERSON,
            ),
            new ObjectClass(
                ObjectClassOid::OID_INET_ORG_PERSON,
                [ObjectClassOid::NAME_INET_ORG_PERSON],
                type: ObjectClassType::StructuralClass,
                superClassOids: [ObjectClassOid::OID_ORGANIZATIONAL_PERSON],
                may: [
                    AttributeTypeOid::NAME_UID,
                    AttributeTypeOid::NAME_MAIL,
                    AttributeTypeOid::NAME_GIVEN_NAME,
                    AttributeTypeOid::NAME_INITIALS,
                    AttributeTypeOid::NAME_DISPLAY_NAME,
                    AttributeTypeOid::NAME_EMPLOYEE_NUMBER,
                    AttributeTypeOid::NAME_MEMBER_OF,
                    AttributeTypeOid::NAME_LABELED_URI,
                    AttributeTypeOid::NAME_JPEG_PHOTO,
                    AttributeTypeOid::NAME_DESCRIPTION,
                ],
                desc: ObjectClassOid::DESC_INET_ORG_PERSON,
            ),
            new ObjectClass(
                ObjectClassOid::OID_GROUP_OF_NAMES,
                [ObjectClassOid::NAME_GROUP_OF_NAMES],
                type: ObjectClassType::StructuralClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                must: [AttributeTypeOid::NAME_MEMBER, AttributeTypeOid::NAME_CN],
                may: [
                    AttributeTypeOid::NAME_DESCRIPTION,
                    AttributeTypeOid::NAME_O,
                    AttributeTypeOid::NAME_OU,
                    AttributeTypeOid::NAME_SEE_ALSO,
                ],
                desc: ObjectClassOid::DESC_GROUP_OF_NAMES,
            ),
            new ObjectClass(
                ObjectClassOid::OID_GROUP_OF_UNIQUE_NAMES,
                [ObjectClassOid::NAME_GROUP_OF_UNIQUE_NAMES],
                type: ObjectClassType::StructuralClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                must: [AttributeTypeOid::NAME_UNIQUE_MEMBER, AttributeTypeOid::NAME_CN],
                may: [
                    AttributeTypeOid::NAME_DESCRIPTION,
                    AttributeTypeOid::NAME_O,
                    AttributeTypeOid::NAME_OU,
                    AttributeTypeOid::NAME_SEE_ALSO,
                ],
                desc: ObjectClassOid::DESC_GROUP_OF_UNIQUE_NAMES,
            ),
            new ObjectClass(
                ObjectClassOid::OID_ORGANIZATIONAL_UNIT,
                [ObjectClassOid::NAME_ORGANIZATIONAL_UNIT],
                type: ObjectClassType::StructuralClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                must: [AttributeTypeOid::NAME_OU],
                may: [
                    AttributeTypeOid::NAME_DESCRIPTION,
                    AttributeTypeOid::NAME_L,
                    AttributeTypeOid::NAME_ST,
                    AttributeTypeOid::NAME_TELEPHONE_NUMBER,
                    AttributeTypeOid::NAME_POSTAL_CODE,
                    AttributeTypeOid::NAME_SEE_ALSO,
                ],
                desc: ObjectClassOid::DESC_ORGANIZATIONAL_UNIT,
            ),
            new ObjectClass(
                ObjectClassOid::OID_ORGANIZATION,
                [ObjectClassOid::NAME_ORGANIZATION],
                type: ObjectClassType::StructuralClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                must: [AttributeTypeOid::NAME_O],
                may: [
                    AttributeTypeOid::NAME_DESCRIPTION,
                    AttributeTypeOid::NAME_L,
                    AttributeTypeOid::NAME_ST,
                    AttributeTypeOid::NAME_C,
                    AttributeTypeOid::NAME_TELEPHONE_NUMBER,
                    AttributeTypeOid::NAME_POSTAL_CODE,
                    AttributeTypeOid::NAME_SEE_ALSO,
                ],
                desc: ObjectClassOid::DESC_ORGANIZATION,
            ),
            new ObjectClass(
                ObjectClassOid::OID_DOMAIN,
                [ObjectClassOid::NAME_DOMAIN],
                type: ObjectClassType::StructuralClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                must: [AttributeTypeOid::NAME_DC],
                may: [
                    AttributeTypeOid::NAME_O,
                    AttributeTypeOid::NAME_DESCRIPTION,
                    AttributeTypeOid::NAME_L,
                    AttributeTypeOid::NAME_ST,
                    AttributeTypeOid::NAME_C,
                ],
                desc: ObjectClassOid::DESC_DOMAIN,
            ),
            new ObjectClass(
                ObjectClassOid::OID_DC_OBJECT,
                [ObjectClassOid::NAME_DC_OBJECT],
                type: ObjectClassType::AuxiliaryClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                must: [AttributeTypeOid::NAME_DC],
                desc: ObjectClassOid::DESC_DC_OBJECT,
            ),
            new ObjectClass(
                ObjectClassOid::OID_SUBSCHEMA,
                [ObjectClassOid::NAME_SUBSCHEMA],
                type: ObjectClassType::AuxiliaryClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                may: [
                    AttributeTypeOid::NAME_DIT_STRUCTURE_RULES,
                    AttributeTypeOid::NAME_NAME_FORMS,
                    AttributeTypeOid::NAME_DIT_CONTENT_RULES,
                    AttributeTypeOid::NAME_OBJECT_CLASSES,
                    AttributeTypeOid::NAME_ATTRIBUTE_TYPES,
                    AttributeTypeOid::NAME_MATCHING_RULES,
                    AttributeTypeOid::NAME_MATCHING_RULE_USE,
                ],
                desc: ObjectClassOid::DESC_SUBSCHEMA,
            ),
            new ObjectClass(
                ObjectClassOid::OID_EXTENSIBLE_OBJECT,
                [ObjectClassOid::NAME_EXTENSIBLE_OBJECT],
                type: ObjectClassType::AuxiliaryClass,
                superClassOids: [ObjectClassOid::OID_TOP],
                desc: ObjectClassOid::DESC_EXTENSIBLE_OBJECT,
            ),
        ];
    }
}
