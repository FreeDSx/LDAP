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

use FreeDSx\Ldap\Schema\Matching\Comparator\BitStringComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class BitStringComparatorTest extends TestCase
{
    private BitStringComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new BitStringComparator();
    }

    public function test_equals_matches_identical_bit_strings(): void
    {
        $result = $this->subject->equals(
            "'0101'B",
            "'0101'B",
        );

        self::assertTrue($result);
    }

    public function test_equals_does_not_match_different_bits(): void
    {
        $result = $this->subject->equals(
            "'0101'B",
            "'0110'B",
        );

        self::assertFalse($result);
    }

    public function test_equals_matches_a_bare_bit_sequence_against_the_quoted_form(): void
    {
        $result = $this->subject->equals(
            "'0101'B",
            '0101',
        );

        self::assertTrue($result);
    }

    public function test_equals_keeps_trailing_zeros_significant(): void
    {
        $result = $this->subject->equals(
            "'0101'B",
            "'01010'B",
        );

        self::assertFalse($result);
    }

    public function test_equals_ignores_surrounding_whitespace(): void
    {
        $result = $this->subject->equals(
            "  '0101'B  ",
            "'0101'B",
        );

        self::assertTrue($result);
    }

    public function test_compare_orders_by_bits(): void
    {
        $result = $this->subject->compare(
            "'0101'B",
            "'0110'B",
        );

        self::assertLessThan(0, $result);
    }

    public function test_substring_matches_within_the_bits(): void
    {
        $result = $this->subject->substringMatches(
            "'010111'B",
            new SubstringAssertion(final: '111'),
        );

        self::assertTrue($result);
    }

    public function test_index_key_is_shared_by_values_holding_the_same_bits(): void
    {
        self::assertSame(
            $this->subject->indexKey(" '0101'B "),
            $this->subject->indexKey("'0101'B"),
        );
    }

    public function test_index_key_differs_when_the_bits_differ(): void
    {
        self::assertNotSame(
            $this->subject->indexKey("'0101'B"),
            $this->subject->indexKey("'1010'B"),
        );
    }

    public function test_index_fragment_is_the_fragment_untouched(): void
    {
        self::assertSame(
            '111',
            $this->subject->indexFragment('111'),
        );
    }
}
