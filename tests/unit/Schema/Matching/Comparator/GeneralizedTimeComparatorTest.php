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

use FreeDSx\Ldap\Schema\Matching\Comparator\GeneralizedTimeComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class GeneralizedTimeComparatorTest extends TestCase
{
    private GeneralizedTimeComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new GeneralizedTimeComparator();
    }

    public function test_equals_same_utc_timestamp(): void
    {
        $result = $this->subject->equals(
            '20060102150405Z',
            '20060102150405Z',
        );

        self::assertTrue($result);
    }

    public function test_equals_utc_z_and_offset_zero(): void
    {
        $result = $this->subject->equals(
            '20060102150405Z',
            '20060102150405+0000',
        );

        self::assertTrue($result);
    }

    public function test_equals_different_times(): void
    {
        $result = $this->subject->equals(
            '20060102150405Z',
            '20060102160405Z',
        );

        self::assertFalse($result);
    }

    public function test_equals_invalid_value_returns_false(): void
    {
        $result = $this->subject->equals(
            'not-a-time',
            '20060102150405Z',
        );

        self::assertFalse($result);
    }

    public function test_compare_earlier_time_is_less(): void
    {
        $result = $this->subject->compare(
            '20060102140405Z',
            '20060102150405Z',
        );

        self::assertLessThan(0, $result);
    }

    public function test_compare_later_time_is_greater(): void
    {
        $result = $this->subject->compare(
            '20060102160405Z',
            '20060102150405Z',
        );

        self::assertGreaterThan(0, $result);
    }

    public function test_compare_equal(): void
    {
        $result = $this->subject->compare(
            '20060102150405Z',
            '20060102150405Z',
        );

        self::assertSame(0, $result);
    }

    public function test_substring_always_returns_false(): void
    {
        $result = $this->subject->substringMatches(
            '20060102150405Z',
            new SubstringAssertion(initial: '2006'),
        );

        self::assertFalse($result);
    }
}
