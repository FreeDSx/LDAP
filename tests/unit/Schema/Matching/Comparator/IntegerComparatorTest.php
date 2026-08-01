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

use FreeDSx\Ldap\Schema\Matching\Comparator\IntegerComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class IntegerComparatorTest extends TestCase
{
    private IntegerComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new IntegerComparator();
    }

    public function test_equals_same_value(): void
    {
        $result = $this->subject->equals('42', '42');

        self::assertTrue($result);
    }

    public function test_equals_equivalent_integer_representations(): void
    {
        $result = $this->subject->equals('042', '42');

        self::assertTrue($result);
    }

    public function test_equals_different_values(): void
    {
        $result = $this->subject->equals('1', '2');

        self::assertFalse($result);
    }

    public function test_compare_equal(): void
    {
        $result = $this->subject->compare('5', '5');

        self::assertSame(0, $result);
    }

    public function test_compare_less_than(): void
    {
        $result = $this->subject->compare('3', '10');

        self::assertLessThan(0, $result);
    }

    public function test_compare_greater_than(): void
    {
        $result = $this->subject->compare('10', '3');

        self::assertGreaterThan(0, $result);
    }

    public function test_substring_always_returns_false(): void
    {
        $result = $this->subject->substringMatches(
            '42',
            new SubstringAssertion(initial: '4'),
        );

        self::assertFalse($result);
    }
}
