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

namespace FreeDSx\Ldap\Schema\Matching;

use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Matching\Comparator\BitMaskComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\BitStringComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\BooleanComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseExactComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreIa5Comparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\DistinguishedNameComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\FirstComponentComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\GeneralizedTimeComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\IntegerComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\NumericStringComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\OctetStringComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\TelephoneNumberComparator;

/**
 * Maps a matching rule OID to the comparator that implements it.
 *
 * A description string names a matching rule but cannot express how it compares, so a rule read from text needs its
 * comparator supplied here.
 *
 * @api
 */
final readonly class MatchingRuleComparatorRegistry
{
    /**
     * @param array<string, MatchingRuleComparatorInterface> $comparators keyed by matching rule OID
     */
    public function __construct(private array $comparators) {}

    /**
     * Builds a registry covering the matching rules this library implements.
     */
    public static function default(): self
    {
        $caseIgnore = new CaseIgnoreComparator();
        $caseExact = new CaseExactComparator();
        $integer = new IntegerComparator();
        $generalizedTime = new GeneralizedTimeComparator();
        $distinguishedName = new DistinguishedNameComparator();
        $caseIgnoreIa5 = new CaseIgnoreIa5Comparator();
        $telephoneNumber = new TelephoneNumberComparator();
        $numericString = new NumericStringComparator();
        $octetString = new OctetStringComparator();

        return new self([
            MatchingRuleOid::OID_OBJECT_IDENTIFIER_MATCH => $caseIgnore,
            MatchingRuleOid::OID_DISTINGUISHED_NAME_MATCH => $distinguishedName,
            MatchingRuleOid::OID_UNIQUE_MEMBER_MATCH => $distinguishedName,
            MatchingRuleOid::OID_CASE_IGNORE_MATCH => $caseIgnore,
            MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH => $caseIgnore,
            MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH => $caseIgnore,
            MatchingRuleOid::OID_CASE_EXACT_MATCH => $caseExact,
            MatchingRuleOid::OID_CASE_EXACT_ORDERING_MATCH => $caseExact,
            MatchingRuleOid::OID_CASE_EXACT_SUBSTRINGS_MATCH => $caseExact,
            MatchingRuleOid::OID_CASE_EXACT_IA5_MATCH => $caseExact,
            MatchingRuleOid::OID_CASE_IGNORE_IA5_MATCH => $caseIgnoreIa5,
            MatchingRuleOid::OID_CASE_IGNORE_IA5_SUBSTRINGS_MATCH => $caseIgnoreIa5,
            MatchingRuleOid::OID_BOOLEAN_MATCH => new BooleanComparator(),
            MatchingRuleOid::OID_INTEGER_MATCH => $integer,
            MatchingRuleOid::OID_INTEGER_ORDERING_MATCH => $integer,
            MatchingRuleOid::OID_OCTET_STRING_MATCH => $octetString,
            MatchingRuleOid::OID_GENERALIZED_TIME_MATCH => $generalizedTime,
            MatchingRuleOid::OID_GENERALIZED_TIME_ORDERING_MATCH => $generalizedTime,
            MatchingRuleOid::OID_TELEPHONE_NUMBER_MATCH => $telephoneNumber,
            MatchingRuleOid::OID_TELEPHONE_NUMBER_SUBSTRINGS_MATCH => $telephoneNumber,
            MatchingRuleOid::OID_NUMERIC_STRING_MATCH => $numericString,
            MatchingRuleOid::OID_NUMERIC_STRING_ORDERING_MATCH => $numericString,
            MatchingRuleOid::OID_NUMERIC_STRING_SUBSTRINGS_MATCH => $numericString,
            // A list is a single DirectoryString here, so caseIgnore covers it without sequence-aware matching.
            MatchingRuleOid::OID_CASE_IGNORE_LIST_MATCH => $caseIgnore,
            MatchingRuleOid::OID_CASE_IGNORE_LIST_SUBSTRINGS_MATCH => $caseIgnore,
            MatchingRuleOid::OID_BIT_STRING_MATCH => new BitStringComparator(),
            // RFC 4530 defines both in terms of octetStringMatch.
            MatchingRuleOid::OID_UUID_MATCH => $octetString,
            MatchingRuleOid::OID_UUID_ORDERING_MATCH => $octetString,
            MatchingRuleOid::OID_INTEGER_FIRST_COMPONENT_MATCH => new FirstComponentComparator($integer),
            MatchingRuleOid::OID_OBJECT_IDENTIFIER_FIRST_COMPONENT_MATCH => new FirstComponentComparator($caseIgnore),
            MatchingRuleOid::OID_BIT_AND_MATCH => new BitMaskComparator(requireAllBits: true),
            MatchingRuleOid::OID_BIT_OR_MATCH => new BitMaskComparator(requireAllBits: false),
        ]);
    }

    /**
     * Returns the comparator for a matching rule OID, or null when the rule is not implemented.
     */
    public function get(string $ruleOid): ?MatchingRuleComparatorInterface
    {
        return $this->comparators[$ruleOid] ?? null;
    }
}
