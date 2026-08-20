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

use FreeDSx\Ldap\Schema\Matching\Comparator\CaseExactComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class CaseExactComparatorTest extends TestCase
{
    private CaseExactComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new CaseExactComparator();
    }

    public function test_equals_same_case(): void
    {
        $result = $this->subject->equals('foo', 'foo');

        self::assertTrue($result);
    }

    public function test_equals_different_case_returns_false(): void
    {
        $result = $this->subject->equals('Foo', 'foo');

        self::assertFalse($result);
    }

    public function test_equals_mismatch(): void
    {
        $result = $this->subject->equals('foo', 'bar');

        self::assertFalse($result);
    }

    public function test_compare_equal(): void
    {
        $result = $this->subject->compare('foo', 'foo');

        self::assertSame(0, $result);
    }

    public function test_compare_case_sensitive(): void
    {
        $result = $this->subject->compare('foo', 'FOO');

        self::assertNotSame(0, $result);
    }

    public function test_substring_case_sensitive_match(): void
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

    public function test_equals_collapses_whitespace_but_keeps_case(): void
    {
        self::assertTrue($this->subject->equals(
            'Foo  Bar',
            'Foo Bar',
        ));
        self::assertFalse($this->subject->equals(
            'Foo  Bar',
            'foo bar',
        ));
    }

    public function test_substring_case_sensitive_with_extra_spaces(): void
    {
        self::assertTrue($this->subject->substringMatches(
            'Foo  Bar',
            new SubstringAssertion(initial: 'Foo Bar'),
        ));
        self::assertFalse($this->subject->substringMatches(
            'Foo  Bar',
            new SubstringAssertion(initial: 'foo bar'),
        ));
    }

    public function test_index_key_is_shared_after_space_collapse(): void
    {
        self::assertSame(
            $this->subject->indexKey('Foo  Bar'),
            $this->subject->indexKey('Foo Bar'),
        );
    }

    public function test_index_key_keeps_case_significant(): void
    {
        self::assertNotSame(
            $this->subject->indexKey('Foo'),
            $this->subject->indexKey('foo'),
        );
    }

    public function test_index_fragment_keeps_its_edge_spaces(): void
    {
        self::assertSame(
            ' Foo',
            $this->subject->indexFragment(' Foo'),
        );
    }
}
