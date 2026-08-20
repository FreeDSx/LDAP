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

use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreIa5Comparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class CaseIgnoreIa5ComparatorTest extends TestCase
{
    private CaseIgnoreIa5Comparator $subject;

    protected function setUp(): void
    {
        $this->subject = new CaseIgnoreIa5Comparator();
    }

    public function test_equals_case_insensitive(): void
    {
        $result = $this->subject->equals('user@example.com', 'USER@EXAMPLE.COM');

        self::assertTrue($result);
    }

    public function test_equals_different_values(): void
    {
        $result = $this->subject->equals('foo@example.com', 'bar@example.com');

        self::assertFalse($result);
    }

    public function test_compare_equal(): void
    {
        $result = $this->subject->compare('foo', 'FOO');

        self::assertSame(0, $result);
    }

    public function test_compare_less_than(): void
    {
        $result = $this->subject->compare('a', 'B');

        self::assertLessThan(0, $result);
    }

    public function test_substring_case_insensitive_match(): void
    {
        $result = $this->subject->substringMatches(
            'user@example.com',
            new SubstringAssertion(initial: 'USER'),
        );

        self::assertTrue($result);
    }

    public function test_index_key_is_shared_by_values_the_rule_calls_equal(): void
    {
        self::assertSame(
            $this->subject->indexKey('Alice@Foo.Bar'),
            $this->subject->indexKey('alice@foo.bar'),
        );
    }

    public function test_index_key_differs_for_values_the_rule_keeps_apart(): void
    {
        self::assertNotSame(
            $this->subject->indexKey('alice@foo.bar'),
            $this->subject->indexKey('bob@foo.bar'),
        );
    }

    public function test_index_fragment_folds_case(): void
    {
        self::assertSame(
            $this->subject->indexKey('user'),
            $this->subject->indexFragment('USER'),
        );
    }
}
