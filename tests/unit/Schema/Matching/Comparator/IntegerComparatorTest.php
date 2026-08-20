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

use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Matching\Comparator\IntegerComparator;
use FreeDSx\Ldap\Schema\Matching\IndexableComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorRegistry;
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

    public function test_equals_rejects_a_value_with_trailing_text(): void
    {
        self::assertFalse($this->subject->equals(
            '99',
            '99abc',
        ));
    }

    public function test_equals_rejects_a_non_numeric_value(): void
    {
        self::assertFalse($this->subject->equals(
            '0',
            'abc',
        ));
        self::assertFalse($this->subject->equals(
            'abc',
            'abc',
        ));
    }

    public function test_equals_beyond_the_platform_integer(): void
    {
        self::assertFalse($this->subject->equals(
            '9223372036854775808',
            '9223372036854775809',
        ));
        self::assertTrue($this->subject->equals(
            '9223372036854775808',
            '09223372036854775808',
        ));
    }

    public function test_equals_signed_values(): void
    {
        self::assertTrue($this->subject->equals(
            '-42',
            '-42',
        ));
        self::assertTrue($this->subject->equals(
            '+42',
            '42',
        ));
        self::assertFalse($this->subject->equals(
            '-42',
            '42',
        ));
        self::assertTrue($this->subject->equals(
            '-0',
            '0',
        ));
    }

    public function test_compare_orders_negatives_below_positives(): void
    {
        self::assertLessThan(
            0,
            $this->subject->compare(
                '-100',
                '3',
            ),
        );
        self::assertGreaterThan(
            0,
            $this->subject->compare(
                '-3',
                '-100',
            ),
        );
    }

    public function test_compare_beyond_the_platform_integer(): void
    {
        self::assertLessThan(
            0,
            $this->subject->compare(
                '9223372036854775807',
                '9223372036854775808',
            ),
        );
    }

    public function test_substring_always_returns_false(): void
    {
        $result = $this->subject->substringMatches(
            '42',
            new SubstringAssertion(initial: '4'),
        );

        self::assertFalse($result);
    }

    /**
     * A store narrows integers with a numeric comparison instead, which a lexical key would not agree with.
     */
    public function test_the_rule_resolves_to_a_comparator_that_is_deliberately_not_indexable(): void
    {
        self::assertNotInstanceOf(
            IndexableComparatorInterface::class,
            MatchingRuleComparatorRegistry::default()->get(MatchingRuleOid::OID_INTEGER_MATCH),
        );
    }
}
