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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Matching\Comparator;

use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class CaseIgnoreComparatorTest extends TestCase
{
    private CaseIgnoreComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new CaseIgnoreComparator();
    }

    public function test_equals_same_case(): void
    {
        $result = $this->subject->equals('foo', 'foo');

        self::assertTrue($result);
    }

    public function test_equals_different_case(): void
    {
        self::assertTrue($this->subject->equals('Foo', 'foo'));
        self::assertTrue($this->subject->equals('FOO', 'foo'));
    }

    public function test_equals_returns_false_on_mismatch(): void
    {
        $result = $this->subject->equals('foo', 'bar');

        self::assertFalse($result);
    }

    public function test_compare_equal_strings(): void
    {
        $result = $this->subject->compare('foo', 'FOO');

        self::assertSame(0, $result);
    }

    public function test_compare_less_than(): void
    {
        $result = $this->subject->compare('a', 'B');

        self::assertLessThan(0, $result);
    }

    public function test_compare_greater_than(): void
    {
        $result = $this->subject->compare('b', 'A');

        self::assertGreaterThan(0, $result);
    }

    public function test_substring_initial_match(): void
    {
        $result = $this->subject->substringMatches(
            'FooBar',
            new SubstringAssertion(initial: 'foo'),
        );

        self::assertTrue($result);
    }

    public function test_substring_initial_no_match(): void
    {
        $result = $this->subject->substringMatches(
            'FooBar',
            new SubstringAssertion(initial: 'bar'),
        );

        self::assertFalse($result);
    }

    public function test_substring_any_match(): void
    {
        $result = $this->subject->substringMatches(
            'FooBarBaz',
            new SubstringAssertion(any: ['BAR']),
        );

        self::assertTrue($result);
    }

    public function test_substring_final_match(): void
    {
        $result = $this->subject->substringMatches(
            'FooBar',
            new SubstringAssertion(final: 'BAR'),
        );

        self::assertTrue($result);
    }

    public function test_substring_final_no_match(): void
    {
        $result = $this->subject->substringMatches(
            'FooBar',
            new SubstringAssertion(final: 'Foo'),
        );

        self::assertFalse($result);
    }

    public function test_substring_combined(): void
    {
        $result = $this->subject->substringMatches(
            'FooBarBaz',
            new SubstringAssertion(
                initial: 'foo',
                any: ['bar'],
                final: 'baz',
            ),
        );

        self::assertTrue($result);
    }

    public function test_equals_collapses_double_space(): void
    {
        $result = $this->subject->equals(
            'Foo  Bar',
            'foo bar',
        );

        self::assertTrue($result);
    }

    public function test_equals_trims_whitespace(): void
    {
        $result = $this->subject->equals(
            '  foo  ',
            'foo',
        );

        self::assertTrue($result);
    }

    public function test_equals_strips_soft_hyphen(): void
    {
        $result = $this->subject->equals(
            "foo\u{00AD}bar",
            'foobar',
        );

        self::assertTrue($result);
    }

    public function test_equals_folds_unicode_space(): void
    {
        $result = $this->subject->equals(
            "foo\u{00A0}bar",
            'foo bar',
        );

        self::assertTrue($result);
    }

    public function test_substring_initial_with_extra_spaces_in_value(): void
    {
        $result = $this->subject->substringMatches(
            'Foo   Bar Baz',
            new SubstringAssertion(initial: 'foo bar'),
        );

        self::assertTrue($result);
    }

    public function test_substring_any_across_collapsed_spaces(): void
    {
        $result = $this->subject->substringMatches(
            'a  b  c',
            new SubstringAssertion(any: ['b c']),
        );

        self::assertTrue($result);
    }

    public function test_substring_final_with_trailing_space_in_value(): void
    {
        $result = $this->subject->substringMatches(
            'foo bar  ',
            new SubstringAssertion(final: 'bar'),
        );

        self::assertTrue($result);
    }

    public function test_compare_equal_after_space_collapse(): void
    {
        $result = $this->subject->compare(
            'a  b',
            'a b',
        );

        self::assertSame(0, $result);
    }
}
