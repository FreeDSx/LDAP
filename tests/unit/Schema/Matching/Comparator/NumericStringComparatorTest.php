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

use FreeDSx\Ldap\Schema\Matching\Comparator\NumericStringComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class NumericStringComparatorTest extends TestCase
{
    private NumericStringComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new NumericStringComparator();
    }

    public function test_equals_treats_spaces_as_insignificant(): void
    {
        $result = $this->subject->equals(
            '1 555 555',
            '1555555',
        );

        self::assertTrue($result);
    }

    public function test_equals_folds_compatibility_digits(): void
    {
        self::assertTrue($this->subject->equals(
            "\u{FF11}\u{FF12}\u{FF13}",
            '123',
        ));
    }

    public function test_equals_does_not_match_different_digits(): void
    {
        $result = $this->subject->equals(
            '1555555',
            '1555556',
        );

        self::assertFalse($result);
    }

    public function test_equals_keeps_leading_zeros_significant(): void
    {
        $result = $this->subject->equals(
            '0123',
            '123',
        );

        self::assertFalse($result);
    }

    public function test_compare_orders_by_code_point(): void
    {
        $result = $this->subject->compare(
            '1 2 3',
            '124',
        );

        self::assertLessThan(0, $result);
    }

    public function test_substring_ignores_spaces_on_both_sides(): void
    {
        $result = $this->subject->substringMatches(
            '1 555 867 5309',
            new SubstringAssertion(any: ['8675']),
        );

        self::assertTrue($result);
    }

    public function test_substring_matches_an_initial_across_a_space(): void
    {
        $result = $this->subject->substringMatches(
            '1 555 867',
            new SubstringAssertion(initial: '1555'),
        );

        self::assertTrue($result);
    }
}
