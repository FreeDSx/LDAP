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
use FreeDSx\Ldap\Schema\Matching\Comparator\BitMaskComparator;
use FreeDSx\Ldap\Schema\Matching\IndexableComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorRegistry;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class BitMaskComparatorTest extends TestCase
{
    public function test_bit_and_all_bits_set(): void
    {
        $subject = new BitMaskComparator(requireAllBits: true);
        $result = $subject->equals('7', '3'); // 0b111 & 0b011 === 0b011

        self::assertTrue($result);
    }

    public function test_bit_and_not_all_bits_set(): void
    {
        $subject = new BitMaskComparator(requireAllBits: true);
        $result = $subject->equals('4', '3'); // 0b100 & 0b011 === 0

        self::assertFalse($result);
    }

    public function test_bit_or_any_bit_set(): void
    {
        $subject = new BitMaskComparator(requireAllBits: false);
        $result = $subject->equals('4', '6'); // 0b100 & 0b110 !== 0

        self::assertTrue($result);
    }

    public function test_bit_or_no_bits_set(): void
    {
        $subject = new BitMaskComparator(requireAllBits: false);
        $result = $subject->equals('8', '7'); // 0b1000 & 0b0111 === 0

        self::assertFalse($result);
    }

    public function test_compare_equal(): void
    {
        $subject = new BitMaskComparator(requireAllBits: true);
        $result = $subject->compare('5', '5');

        self::assertSame(0, $result);
    }

    public function test_compare_less_than(): void
    {
        $subject = new BitMaskComparator(requireAllBits: true);
        $result = $subject->compare('3', '10');

        self::assertLessThan(0, $result);
    }

    public function test_substring_always_returns_false(): void
    {
        $subject = new BitMaskComparator(requireAllBits: true);
        $result = $subject->substringMatches(
            '7',
            new SubstringAssertion(initial: '7'),
        );

        self::assertFalse($result);
    }

    /**
     * A mask test is not an equivalence relation, so no key can stand in for it.
     */
    public function test_the_rule_resolves_to_a_comparator_that_is_deliberately_not_indexable(): void
    {
        self::assertNotInstanceOf(
            IndexableComparatorInterface::class,
            MatchingRuleComparatorRegistry::default()->get(MatchingRuleOid::OID_BIT_AND_MATCH),
        );
    }
}
