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
use FreeDSx\Ldap\Schema\Matching\Comparator\BooleanComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseExactComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreIa5Comparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\DistinguishedNameComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\GeneralizedTimeComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\IntegerComparator;
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
            MatchingRuleOid::OID_CASE_IGNORE_IA5_MATCH => new CaseIgnoreIa5Comparator(),
            MatchingRuleOid::OID_BOOLEAN_MATCH => new BooleanComparator(),
            MatchingRuleOid::OID_INTEGER_MATCH => $integer,
            MatchingRuleOid::OID_INTEGER_ORDERING_MATCH => $integer,
            MatchingRuleOid::OID_OCTET_STRING_MATCH => new OctetStringComparator(),
            MatchingRuleOid::OID_GENERALIZED_TIME_MATCH => $generalizedTime,
            MatchingRuleOid::OID_GENERALIZED_TIME_ORDERING_MATCH => $generalizedTime,
            MatchingRuleOid::OID_TELEPHONE_NUMBER_MATCH => new TelephoneNumberComparator(),
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
