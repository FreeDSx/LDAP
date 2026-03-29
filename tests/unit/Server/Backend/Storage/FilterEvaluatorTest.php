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

    public function test_matching_rule_unknown_returns_false(): void
    {
        $filter = new MatchingRuleFilter(
            '1.2.3.4.5.unknown',
            'cn',
            'Alice',
        );
        self::assertFalse($this->subject->evaluate(
            $this->entry,
            $filter
        ));
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

    public function test_unknown_filter_type_returns_false(): void
    {
        self::assertFalse($this->subject->evaluate(
            $this->entry,
            $this->createMock(FilterInterface::class)
        ));
    }
}
