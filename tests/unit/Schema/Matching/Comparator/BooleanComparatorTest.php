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

use FreeDSx\Ldap\Schema\Matching\Comparator\BooleanComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class BooleanComparatorTest extends TestCase
{
    private BooleanComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new BooleanComparator();
    }

    public function test_equals_true_literal(): void
    {
        $result = $this->subject->equals('TRUE', 'TRUE');

        self::assertTrue($result);
    }

    public function test_equals_case_insensitive(): void
    {
        $result = $this->subject->equals('true', 'TRUE');

        self::assertTrue($result);
    }

    public function test_equals_false_literal(): void
    {
        $result = $this->subject->equals('FALSE', 'FALSE');

        self::assertTrue($result);
    }

    public function test_equals_true_vs_false(): void
    {
        $result = $this->subject->equals('TRUE', 'FALSE');

        self::assertFalse($result);
    }

    public function test_compare_equal(): void
    {
        $result = $this->subject->compare('TRUE', 'TRUE');

        self::assertSame(0, $result);
    }

    public function test_substring_always_returns_false(): void
    {
        $result = $this->subject->substringMatches(
            'TRUE',
            new SubstringAssertion(initial: 'T'),
        );

        self::assertFalse($result);
    }
}
