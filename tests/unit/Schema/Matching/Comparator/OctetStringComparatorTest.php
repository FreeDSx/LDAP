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

use FreeDSx\Ldap\Schema\Matching\Comparator\OctetStringComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class OctetStringComparatorTest extends TestCase
{
    private OctetStringComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new OctetStringComparator();
    }

    public function test_equals_identical_bytes(): void
    {
        $result = $this->subject->equals('foo', 'foo');

        self::assertTrue($result);
    }

    public function test_equals_case_sensitive(): void
    {
        $result = $this->subject->equals('Foo', 'foo');

        self::assertFalse($result);
    }

    public function test_compare_equal(): void
    {
        $result = $this->subject->compare('abc', 'abc');

        self::assertSame(0, $result);
    }

    public function test_compare_less_than(): void
    {
        $result = $this->subject->compare('abc', 'abd');

        self::assertLessThan(0, $result);
    }

    public function test_substring_case_sensitive_initial(): void
    {
        $result = $this->subject->substringMatches(
            'FooBar',
            new SubstringAssertion(initial: 'Foo'),
        );

        self::assertTrue($result);
    }

    public function test_substring_case_sensitive_no_match(): void
    {
        $result = $this->subject->substringMatches(
            'FooBar',
            new SubstringAssertion(initial: 'foo'),
        );

        self::assertFalse($result);
    }

    public function test_substring_any_and_final(): void
    {
        $result = $this->subject->substringMatches(
            'FooBarBaz',
            new SubstringAssertion(
                any: ['Bar'],
                final: 'Baz',
            ),
        );

        self::assertTrue($result);
    }
}
