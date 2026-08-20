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

use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\FirstComponentComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\IntegerComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class FirstComponentComparatorTest extends TestCase
{
    private const OBJECT_CLASS_DEFINITION = "( 2.5.6.6 NAME 'person' DESC 'natural persons' SUP 2.5.6.0 STRUCTURAL MUST ( sn $ cn ) )";

    private FirstComponentComparator $subject;

    private FirstComponentComparator $integerSubject;

    protected function setUp(): void
    {
        $this->subject = new FirstComponentComparator(new CaseIgnoreComparator());
        $this->integerSubject = new FirstComponentComparator(new IntegerComparator());
    }

    public function test_equals_matches_a_bare_oid_against_a_definition(): void
    {
        $result = $this->subject->equals(
            self::OBJECT_CLASS_DEFINITION,
            '2.5.6.6',
        );

        self::assertTrue($result);
    }

    public function test_equals_does_not_match_a_different_oid(): void
    {
        $result = $this->subject->equals(
            self::OBJECT_CLASS_DEFINITION,
            '2.5.6.7',
        );

        self::assertFalse($result);
    }

    public function test_equals_does_not_match_an_oid_appearing_later_in_the_definition(): void
    {
        // 2.5.6.0 is the SUP, not the first component.
        $result = $this->subject->equals(
            self::OBJECT_CLASS_DEFINITION,
            '2.5.6.0',
        );

        self::assertFalse($result);
    }

    public function test_equals_matches_two_definitions_sharing_a_first_component(): void
    {
        $result = $this->subject->equals(
            self::OBJECT_CLASS_DEFINITION,
            "( 2.5.6.6 NAME 'somethingElse' )",
        );

        self::assertTrue($result);
    }

    public function test_equals_tolerates_absent_whitespace_after_the_parenthesis(): void
    {
        $result = $this->subject->equals(
            "(2.5.6.6 NAME 'person')",
            '2.5.6.6',
        );

        self::assertTrue($result);
    }

    public function test_equals_matches_a_single_component_definition(): void
    {
        $result = $this->subject->equals(
            '( 2.5.6.6 )',
            '2.5.6.6',
        );

        self::assertTrue($result);
    }

    public function test_equals_compares_two_bare_values_whole(): void
    {
        $result = $this->subject->equals(
            '2.5.6.6',
            '2.5.6.6',
        );

        self::assertTrue($result);
    }

    public function test_equals_on_the_integer_variant_matches_the_leading_number(): void
    {
        $result = $this->integerSubject->equals(
            '( 2 NAME \'rule\' )',
            '2',
        );

        self::assertTrue($result);
    }

    public function test_equals_on_the_integer_variant_ignores_leading_zeros(): void
    {
        $result = $this->integerSubject->equals(
            '( 007 NAME \'rule\' )',
            '7',
        );

        self::assertTrue($result);
    }

    public function test_compare_orders_by_the_first_component(): void
    {
        $result = $this->integerSubject->compare(
            '( 2 NAME \'a\' )',
            '( 10 NAME \'b\' )',
        );

        self::assertLessThan(0, $result);
    }

    public function test_substring_matches_against_the_first_component_only(): void
    {
        $result = $this->subject->substringMatches(
            self::OBJECT_CLASS_DEFINITION,
            new SubstringAssertion(initial: '2.5.6'),
        );

        self::assertTrue($result);
    }

    public function test_substring_does_not_match_text_outside_the_first_component(): void
    {
        $result = $this->subject->substringMatches(
            self::OBJECT_CLASS_DEFINITION,
            new SubstringAssertion(any: ['person']),
        );

        self::assertFalse($result);
    }

    public function test_index_key_is_shared_by_a_definition_and_its_bare_first_component(): void
    {
        self::assertSame(
            $this->subject->indexKey(self::OBJECT_CLASS_DEFINITION),
            $this->subject->indexKey('2.5.6.6'),
        );
    }

    public function test_index_key_is_null_when_the_component_comparator_is_not_indexable(): void
    {
        self::assertNull($this->integerSubject->indexKey('( 42 NAME )'));
    }
}
