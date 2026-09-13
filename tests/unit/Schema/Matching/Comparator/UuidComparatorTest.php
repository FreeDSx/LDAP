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

use FreeDSx\Ldap\Schema\Matching\Comparator\UuidComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class UuidComparatorTest extends TestCase
{
    private UuidComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new UuidComparator();
    }

    public function test_equals_identical_values(): void
    {
        $result = $this->subject->equals(
            '597ae2f6-16a6-1027-98f4-d28b5365dc14',
            '597ae2f6-16a6-1027-98f4-d28b5365dc14',
        );

        self::assertTrue($result);
    }

    public function test_equals_ignores_the_case_of_hex_digits(): void
    {
        $result = $this->subject->equals(
            '597ae2f6-16a6-1027-98f4-d28b5365dc14',
            '597AE2F6-16A6-1027-98F4-D28B5365DC14',
        );

        self::assertTrue($result);
    }

    public function test_equals_different_values(): void
    {
        $result = $this->subject->equals(
            '597ae2f6-16a6-1027-98f4-d28b5365dc14',
            '597ae2f6-16a6-1027-98f4-d28b5365dc15',
        );

        self::assertFalse($result);
    }

    public function test_compare_ignores_the_case_of_hex_digits(): void
    {
        $result = $this->subject->compare(
            '597ae2f6-16a6-1027-98f4-d28b5365dc14',
            '597AE2F6-16A6-1027-98F4-D28B5365DC14',
        );

        self::assertSame(
            0,
            $result,
        );
    }

    public function test_compare_orders_by_the_octets_of_the_lower_case_form(): void
    {
        $result = $this->subject->compare(
            '0000000A-0000-0000-0000-000000000000',
            '0000000b-0000-0000-0000-000000000000',
        );

        self::assertLessThan(
            0,
            $result,
        );
    }

    public function test_substring_always_returns_false(): void
    {
        $result = $this->subject->substringMatches(
            '597ae2f6-16a6-1027-98f4-d28b5365dc14',
            new SubstringAssertion(initial: '597a'),
        );

        self::assertFalse($result);
    }

    public function test_index_key_is_shared_by_either_case_of_a_value(): void
    {
        self::assertSame(
            $this->subject->indexKey('597ae2f6-16a6-1027-98f4-d28b5365dc14'),
            $this->subject->indexKey('597AE2F6-16A6-1027-98F4-D28B5365DC14'),
        );
    }

    public function test_index_fragment_is_null_because_the_rule_has_no_substring_form(): void
    {
        self::assertNull($this->subject->indexFragment('597a'));
    }
}
