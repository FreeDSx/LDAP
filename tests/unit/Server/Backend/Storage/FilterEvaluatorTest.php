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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluator;
use PHPUnit\Framework\TestCase;

final class FilterEvaluatorTest extends TestCase
{
    private FilterEvaluator $subject;

    private Entry $entry;

    protected function setUp(): void
    {
        $this->subject = new FilterEvaluator();

        $this->entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('mail', 'alice@example.com'),
            new Attribute('objectClass', 'inetOrgPerson', 'person', 'top'),
            new Attribute('uid', 'asmith'),
            new Attribute('uidNumber', '1001'),
        );
    }

    public function test_present_returns_true_when_attribute_exists(): void
    {
        self::assertTrue(
            $this->subject->evaluate($this->entry, new PresentFilter('cn'))
        );
    }

    public function test_present_returns_false_when_attribute_missing(): void
    {
        self::assertFalse(
            $this->subject->evaluate($this->entry, new PresentFilter('telephoneNumber'))
        );
    }

    public function test_present_is_case_insensitive_for_attribute_name(): void
    {
        self::assertTrue(
            $this->subject->evaluate($this->entry, new PresentFilter('CN'))
        );
    }

    public function test_equality_matches_value(): void
    {
        self::assertTrue(
            $this->subject->evaluate($this->entry, Filters::equal('cn', 'Alice'))
        );
    }

    public function test_equality_is_case_insensitive(): void
    {
        self::assertTrue(
            $this->subject->evaluate($this->entry, Filters::equal('cn', 'ALICE'))
        );
    }

    public function test_equality_returns_false_when_no_match(): void
    {
        self::assertFalse(
            $this->subject->evaluate($this->entry, Filters::equal('cn', 'Bob'))
        );
    }

    public function test_equality_returns_false_when_attribute_missing(): void
    {
        self::assertFalse(
            $this->subject->evaluate($this->entry, Filters::equal('telephoneNumber', '555'))
        );
    }

    public function test_equality_matches_any_value_in_multivalued_attribute(): void
    {
        self::assertTrue(
            $this->subject->evaluate($this->entry, Filters::equal('objectClass', 'person'))
        );
    }

    public function test_substring_startswith(): void
    {
        $filter = (new SubstringFilter('cn'))->setStartsWith('Ali');
        self::assertTrue($this->subject->evaluate($this->entry, $filter));
    }

    public function test_substring_endswith(): void
    {
        $filter = (new SubstringFilter('cn'))->setEndsWith('ice');
        self::assertTrue($this->subject->evaluate($this->entry, $filter));
    }

    public function test_substring_contains(): void
    {
        $filter = (new SubstringFilter('mail'))->setContains('example');
        self::assertTrue($this->subject->evaluate($this->entry, $filter));
    }

    public function test_substring_all_parts_must_match_same_value(): void
    {
        // startsWith from cn, endsWith from sn — can't match same value
        $filter = (new SubstringFilter('cn'))
            ->setStartsWith('Ali')
            ->setEndsWith('Smith');
        self::assertFalse($this->subject->evaluate($this->entry, $filter));
    }

    public function test_substring_is_case_insensitive(): void
    {
        $filter = (new SubstringFilter('cn'))->setStartsWith('ALI');
        self::assertTrue($this->subject->evaluate($this->entry, $filter));
    }

    public function test_substring_returns_false_when_no_match(): void
    {
        $filter = (new SubstringFilter('cn'))->setStartsWith('Bob');
        self::assertFalse($this->subject->evaluate($this->entry, $filter));
    }

    public function test_substring_any_does_not_match_within_initial_portion(): void
    {
        // RFC 4511 §4.5.1.7.1: 'any' must appear AFTER the initial match.
        // "testing" starts with "test" (positions 0-3); the 'any' "t" must be
        // found at position 4+. "ing" has no "t", so the filter must not match.
        $entry = new Entry(
            new Dn('cn=testing,dc=example,dc=com'),
            new Attribute('cn', 'testing'),
        );
        $filter = (new SubstringFilter('cn'))
            ->setStartsWith('test')
            ->setContains('t');

        self::assertFalse($this->subject->evaluate($entry, $filter));
    }

    public function test_substring_any_matches_after_initial_portion(): void
    {
        // "testting" has a second "t" at position 4, which is after the "test" initial.
        $entry = new Entry(
            new Dn('cn=testting,dc=example,dc=com'),
            new Attribute('cn', 'testting'),
        );
        $filter = (new SubstringFilter('cn'))
            ->setStartsWith('test')
            ->setContains('t');

        self::assertTrue($this->subject->evaluate($entry, $filter));
    }

    public function test_substring_final_requires_distinct_occurrence_from_any(): void
    {
        // RFC 4511 §4.5.1.7.1: 'final' must start after the last 'any' match.
        // Filter *foo*foo against value "foo": the 'any' match consumes "foo" at [0,2],
        // leaving nothing for 'final' to start at position >= 3 — no match.
        $entry = new Entry(
            new Dn('cn=foo,dc=example,dc=com'),
            new Attribute('cn', 'foo'),
        );
        $filter = (new SubstringFilter('cn'))
            ->setContains('foo')
            ->setEndsWith('foo');

        self::assertFalse($this->subject->evaluate($entry, $filter));
    }

    public function test_substring_final_matches_after_any_when_two_occurrences_exist(): void
    {
        // "foofoo" has two non-overlapping occurrences: 'any' at [0,2], 'final' at [3,5].
        $entry = new Entry(
            new Dn('cn=foofoo,dc=example,dc=com'),
            new Attribute('cn', 'foofoo'),
        );
        $filter = (new SubstringFilter('cn'))
            ->setContains('foo')
            ->setEndsWith('foo');

        self::assertTrue($this->subject->evaluate($entry, $filter));
    }

    public function test_substring_ordered_contains(): void
    {
        $filter = (new SubstringFilter('mail'))
            ->setContains('alice', 'example');
        self::assertTrue($this->subject->evaluate($this->entry, $filter));
    }

    public function test_substring_ordered_contains_rejects_wrong_order(): void
    {
        $filter = (new SubstringFilter('mail'))
            ->setContains('example', 'alice');
        self::assertFalse($this->subject->evaluate($this->entry, $filter));
    }

    public function test_gte_matches_equal_value(): void
    {
        self::assertTrue(
            $this->subject->evaluate($this->entry, Filters::greaterThanOrEqual('uidNumber', '1001'))
        );
    }

    public function test_gte_matches_greater_value(): void
    {
        self::assertTrue(
            $this->subject->evaluate($this->entry, Filters::greaterThanOrEqual('uidNumber', '1000'))
        );
    }

    public function test_gte_returns_false_when_less(): void
    {
        self::assertFalse(
            $this->subject->evaluate($this->entry, Filters::greaterThanOrEqual('uidNumber', '2000'))
        );
    }

    public function test_lte_matches_equal_value(): void
    {
        self::assertTrue(
            $this->subject->evaluate($this->entry, Filters::lessThanOrEqual('uidNumber', '1001'))
        );
    }

    public function test_lte_matches_lesser_value(): void
    {
        self::assertTrue(
            $this->subject->evaluate($this->entry, Filters::lessThanOrEqual('uidNumber', '9999'))
        );
    }

    public function test_lte_returns_false_when_greater(): void
    {
        self::assertFalse(
            $this->subject->evaluate($this->entry, Filters::lessThanOrEqual('uidNumber', '500'))
        );
    }

    public function test_gte_compares_numbers_as_integers(): void
    {
        // '10' >= '5' must be true numerically; lexicographically '10' < '5'
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('count', '10'),
        );

        self::assertTrue(
            $this->subject->evaluate($entry, Filters::greaterThanOrEqual('count', '5'))
        );
    }

    public function test_gte_does_not_treat_scientific_notation_as_numeric(): void
    {
        // '1e1' is not ctype_digit, so it falls back to lexicographic comparison.
        // Lexicographically '1e1' < '5', so gte('5') should be false.
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('count', '1e1'),
        );

        self::assertFalse(
            $this->subject->evaluate(
                $entry,
                Filters::greaterThanOrEqual('count', '5')
            ),
        );
    }

    public function test_gte_preserves_leading_zeros_as_strings(): void
    {
        // '007' has a leading zero, so ctype_digit still returns true but the value
        // integer-compares as 7, which is less than 10 — gte('10') must be false.
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('employeeId', '007'),
        );

        self::assertFalse(
            $this->subject->evaluate(
                $entry,
                Filters::greaterThanOrEqual('employeeId', '10')
            )
        );
    }

    public function test_approximate_matches_equal_value(): void
    {
        self::assertTrue(
            $this->subject->evaluate($this->entry, new ApproximateFilter('cn', 'Alice'))
        );
    }

    public function test_approximate_is_case_insensitive(): void
    {
        self::assertTrue(
            $this->subject->evaluate(
                $this->entry,
                new ApproximateFilter('cn', 'ALICE')
            )
        );
    }

    public function test_and_returns_true_when_all_match(): void
    {
        $filter = Filters::and(
            Filters::equal('cn', 'Alice'),
            Filters::equal('sn', 'Smith'),
        );
        self::assertTrue($this->subject->evaluate(
            $this->entry,
            $filter,
        ));
    }

    public function test_and_returns_false_when_one_does_not_match(): void
    {
        $filter = Filters::and(
            Filters::equal('cn', 'Alice'),
            Filters::equal('sn', 'Jones'),
        );

        self::assertFalse($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_or_returns_true_when_one_matches(): void
    {
        $filter = Filters::or(
            Filters::equal('cn', 'Bob'),
            Filters::equal('cn', 'Alice'),
        );
        self::assertTrue($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_or_returns_false_when_none_match(): void
    {
        $filter = Filters::or(
            Filters::equal('cn', 'Bob'),
            Filters::equal('cn', 'Charlie'),
        );
        self::assertFalse($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_not_negates_match(): void
    {
        $filter = Filters::not(Filters::equal('cn', 'Alice'));
        self::assertFalse($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_not_negates_non_match(): void
    {
        $filter = Filters::not(Filters::equal('cn', 'Bob'));
        self::assertTrue($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_nested_and_or(): void
    {
        $filter = Filters::and(
            Filters::equal('objectClass', 'inetOrgPerson'),
            Filters::or(
                Filters::equal('cn', 'Bob'),
                Filters::equal('sn', 'Smith'),
            ),
        );
        self::assertTrue($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_matching_rule_default_case_ignore(): void
    {
        $filter = new MatchingRuleFilter(
            null,
            'cn',
            'ALICE',
        );
        self::assertTrue($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_matching_rule_case_exact_match(): void
    {
        $filter = new MatchingRuleFilter(
            '2.5.13.5',
            'cn',
            'Alice',
        );
        self::assertTrue($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_matching_rule_case_exact_no_match(): void
    {
        $filter = new MatchingRuleFilter(
            '2.5.13.5',
            'cn',
            'ALICE',
        );
        self::assertFalse($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_matching_rule_bit_and(): void
    {
        // uidNumber = 1001 = 0b1111101001
        // filter value = 8 = 0b0000001000 (bit 3 set)
        // 1001 & 8 = 8 => true
        $filter = new MatchingRuleFilter(
            '1.2.840.113556.1.4.803',
            'uidNumber',
            '8',
        );
        self::assertTrue($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_matching_rule_bit_and_no_match(): void
    {
        // 1001 & 2 = 0 => false
        $filter = new MatchingRuleFilter(
            '1.2.840.113556.1.4.803',
            'uidNumber',
            '2',
        );
        self::assertFalse($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_matching_rule_unknown_throws_inappropriate_matching(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INAPPROPRIATE_MATCHING);

        $this->subject->evaluate(
            $this->entry,
            new MatchingRuleFilter('1.2.3.4.5.unknown', 'cn', 'Alice'),
        );
    }

    public function test_matching_rule_dn_attributes(): void
    {
        $filter = new MatchingRuleFilter(
            null,
            'cn',
            'alice',
            true,
        );
        // The DN is cn=Alice,dc=example,dc=com — 'alice' matches the RDN value
        self::assertTrue($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_matching_rule_dn_attributes_includes_multivalued_rdn_components(): void
    {
        $entry = new Entry(
            new Dn('cn=John+uid=jdoe,dc=example,dc=com'),
            new Attribute('cn', 'John'),
        );

        $filter = new MatchingRuleFilter(
            null,
            'uid',
            'jdoe',
            true,
        );

        self::assertTrue($this->subject->evaluate(
            $entry,
            $filter,
        ));
    }

    public function test_matching_rule_dn_attributes_filters_by_attribute_name(): void
    {
        // Filter targets 'uid', DN has dc=example — must NOT match "example" via the dc component.
        $filter = new MatchingRuleFilter(
            null,
            'uid',
            'example',
            true,
        );

        self::assertFalse($this->subject->evaluate(
            $this->entry,
            $filter,
        ));
    }

    public function test_matching_rule_dn_attributes_without_attribute_name_matches_any_component(): void
    {
        // No attribute name set + dnAttributes — should match any RDN component value.
        $filter = new MatchingRuleFilter(
            null,
            null,
            'example',
            true,
        );

        self::assertTrue($this->subject->evaluate(
            $this->entry,
            $filter,
        ));
    }

    public function test_matching_rule_null_attribute_matches_all(): void
    {
        // No attribute name set — should match against all attribute values
        $filter = new MatchingRuleFilter(
            null,
            null,
            'Smith',
        );
        self::assertTrue($this->subject->evaluate(
            $this->entry,
            $filter
        ));
    }

    public function test_not_returns_false_when_attribute_is_absent(): void
    {
        // RFC 4511 §4.5.1: NOT(UNDEFINED) = UNDEFINED, which maps to false.
        // An entry missing "description" must NOT match (!(description=test)).
        self::assertFalse(
            $this->subject->evaluate(
                $this->entry,
                Filters::not(Filters::equal('description', 'test')),
            ),
        );
    }

    public function test_not_present_on_absent_attribute_returns_true(): void
    {
        // PresentFilter is definitively FALSE (not UNDEFINED) when absent.
        // NOT(FALSE) = TRUE, so (!(description=*)) matches.
        self::assertTrue(
            $this->subject->evaluate(
                $this->entry,
                Filters::not(new PresentFilter('description')),
            ),
        );
    }

    public function test_and_with_undefined_child_returns_false(): void
    {
        // AND(TRUE, UNDEFINED) = UNDEFINED → false at the public boundary.
        $filter = Filters::and(
            Filters::equal('cn', 'Alice'),
            Filters::equal('description', 'test'),
        );

        self::assertFalse($this->subject->evaluate(
            $this->entry,
            $filter,
        ));
    }

    public function test_or_with_undefined_child_returns_false(): void
    {
        // OR(FALSE, UNDEFINED) = UNDEFINED → false at the public boundary.
        $filter = Filters::or(
            Filters::equal('cn', 'Bob'),
            Filters::equal('description', 'test'),
        );

        self::assertFalse($this->subject->evaluate(
            $this->entry,
            $filter,
        ));
    }

    public function test_or_with_true_and_undefined_returns_true(): void
    {
        // OR(TRUE, UNDEFINED) = TRUE — short-circuits on the first TRUE.
        $filter = Filters::or(
            Filters::equal('cn', 'Alice'),
            Filters::equal('description', 'test'),
        );

        self::assertTrue($this->subject->evaluate(
            $this->entry,
            $filter,
        ));
    }

    public function test_and_with_false_and_undefined_returns_false(): void
    {
        // AND(FALSE, UNDEFINED) = FALSE — short-circuits on the first FALSE.
        $filter = Filters::and(
            Filters::equal('cn', 'Bob'),
            Filters::equal('description', 'test'),
        );

        self::assertFalse($this->subject->evaluate(
            $this->entry,
            $filter,
        ));
    }

    public function test_unknown_filter_type_throws_protocol_error(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->subject->evaluate(
            $this->entry,
            $this->createMock(FilterInterface::class),
        );
    }

    public function test_equality_matches_attribute_with_mixed_case_name_on_entry(): void
    {
        $entry = new Entry(
            new Dn('cn=Bob,dc=example,dc=com'),
            new Attribute('CN', 'Bob'),
        );

        self::assertTrue($this->subject->evaluate(
            $entry,
            Filters::equal('cn', 'Bob'),
        ));
    }

    public function test_equality_with_attribute_options_in_filter_matches_same_options_on_entry(): void
    {
        $entry = new Entry(
            new Dn('cn=Bob,dc=example,dc=com'),
            new Attribute('cn;lang-en', 'Hello'),
            new Attribute('cn;lang-de', 'Hallo'),
        );

        self::assertTrue($this->subject->evaluate(
            $entry,
            Filters::equal('cn;lang-en', 'Hello'),
        ));
        self::assertFalse($this->subject->evaluate(
            $entry,
            Filters::equal('cn;lang-en', 'Hallo'),
        ));
    }

    public function test_equality_with_attribute_options_in_filter_does_not_match_base_only_entry(): void
    {
        $entry = new Entry(
            new Dn('cn=Bob,dc=example,dc=com'),
            new Attribute('cn', 'Hello'),
        );

        self::assertFalse($this->subject->evaluate(
            $entry,
            Filters::equal('cn;lang-en', 'Hello'),
        ));
    }

    public function test_equality_filter_without_options_matches_any_option_variant_on_entry(): void
    {
        $entry = new Entry(
            new Dn('cn=Bob,dc=example,dc=com'),
            new Attribute('cn;lang-en', 'Hello'),
        );

        self::assertTrue($this->subject->evaluate(
            $entry,
            Filters::equal('cn', 'Hello'),
        ));
    }

    public function test_equality_multi_valued_attribute_matches_second_value(): void
    {
        $entry = new Entry(
            new Dn('cn=Multi,dc=example,dc=com'),
            new Attribute('mailAlias', 'a@foo.bar', 'b@foo.bar', 'c@foo.bar'),
        );

        self::assertTrue($this->subject->evaluate(
            $entry,
            Filters::equal('mailAlias', 'b@foo.bar'),
        ));
    }

    public function test_substring_present_absent_and_options_conformance(): void
    {
        $entry = new Entry(
            new Dn('cn=Ann,dc=example,dc=com'),
            new Attribute('cn;lang-en', 'Annabelle'),
        );

        $filter = (new SubstringFilter('cn'))->setStartsWith('Ann');
        self::assertTrue($this->subject->evaluate($entry, $filter));

        $filterMiss = (new SubstringFilter('sn'))->setStartsWith('Ann');
        self::assertFalse($this->subject->evaluate($entry, $filterMiss));
    }

    public function test_gte_undefined_when_attribute_absent(): void
    {
        self::assertFalse($this->subject->evaluate(
            $this->entry,
            Filters::greaterThanOrEqual('employeeNumber', '1'),
        ));
    }

    public function test_lte_undefined_when_attribute_absent(): void
    {
        self::assertFalse($this->subject->evaluate(
            $this->entry,
            Filters::lessThanOrEqual('employeeNumber', '1'),
        ));
    }

    public function test_approximate_undefined_when_attribute_absent(): void
    {
        self::assertFalse($this->subject->evaluate(
            $this->entry,
            new ApproximateFilter('employeeNumber', '1'),
        ));
    }

    public function test_same_filter_against_many_entries_produces_consistent_results(): void
    {
        $filter = Filters::equal('cn', 'Alice');

        $matching = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
        );
        $nonMatching = new Entry(
            new Dn('cn=Bob,dc=example,dc=com'),
            new Attribute('cn', 'Bob'),
        );

        for ($i = 0; $i < 50; $i++) {
            self::assertTrue($this->subject->evaluate($matching, $filter));
            self::assertFalse($this->subject->evaluate($nonMatching, $filter));
        }
    }

    public function test_same_substring_filter_against_many_entries_is_stable(): void
    {
        $filter = (new SubstringFilter('mail'))
            ->setStartsWith('alice')
            ->setContains('example')
            ->setEndsWith('com');

        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('mail', 'alice@example.com'),
        );

        for ($i = 0; $i < 25; $i++) {
            self::assertTrue($this->subject->evaluate($entry, $filter));
        }
    }

    public function test_same_gte_filter_against_digit_and_non_digit_entries_is_stable(): void
    {
        $filter = Filters::greaterThanOrEqual('uidNumber', '100');

        $digitMatches = new Entry(
            new Dn('cn=One,dc=example,dc=com'),
            new Attribute('uidNumber', '500'),
        );
        $digitMisses = new Entry(
            new Dn('cn=Two,dc=example,dc=com'),
            new Attribute('uidNumber', '99'),
        );

        for ($i = 0; $i < 25; $i++) {
            self::assertTrue($this->subject->evaluate($digitMatches, $filter));
            self::assertFalse($this->subject->evaluate($digitMisses, $filter));
        }
    }

    /**
     * Guards against evaluate() stashing compiled state on the filter; serialize catches nested composite mutations too.
     */
    public function test_filter_is_not_mutated_by_evaluation(): void
    {
        $filter = Filters::and(
            Filters::equal('cn', 'Alice'),
            Filters::or(
                Filters::equal('sn', 'Smith'),
                Filters::greaterThanOrEqual('uidNumber', '100'),
            ),
        );
        $snapshot = serialize($filter);

        $this->subject->evaluate($this->entry, $filter);
        $this->subject->evaluate($this->entry, $filter);

        self::assertSame(
            $snapshot,
            serialize($filter),
        );
    }

    public function test_substring_filter_is_not_mutated_by_evaluation(): void
    {
        $filter = (new SubstringFilter('mail'))
            ->setStartsWith('alice')
            ->setContains('example')
            ->setEndsWith('com');
        $snapshot = serialize($filter);

        $this->subject->evaluate($this->entry, $filter);
        $this->subject->evaluate($this->entry, $filter);

        self::assertSame(
            $snapshot,
            serialize($filter),
        );
    }
}
