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
use FreeDSx\Ldap\Schema\Matching\Comparator\NameAndOptionalUidComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class NameAndOptionalUidComparatorTest extends TestCase
{
    private NameAndOptionalUidComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new NameAndOptionalUidComparator();
    }

    public function test_equals_ignores_dn_spacing_and_case(): void
    {
        $result = $this->subject->equals(
            'CN=Admin, DC=Foo',
            'cn=admin,dc=foo',
        );

        self::assertTrue($result);
    }

    public function test_equals_matches_the_dn_and_the_identifier_together(): void
    {
        $result = $this->subject->equals(
            "CN=Admin, DC=Foo#'0101'B",
            "cn=admin,dc=foo#'0101'B",
        );

        self::assertTrue($result);
    }

    public function test_equals_is_false_when_only_one_side_carries_an_identifier(): void
    {
        $result = $this->subject->equals(
            "cn=admin,dc=foo#'0101'B",
            'cn=admin,dc=foo',
        );

        self::assertFalse($result);
    }

    public function test_equals_is_false_when_the_identifiers_differ(): void
    {
        $result = $this->subject->equals(
            "cn=admin,dc=foo#'0101'B",
            "cn=admin,dc=foo#'1010'B",
        );

        self::assertFalse($result);
    }

    public function test_substring_always_returns_false(): void
    {
        $result = $this->subject->substringMatches(
            'cn=admin,dc=foo',
            new SubstringAssertion(initial: 'cn=admin'),
        );

        self::assertFalse($result);
    }

    public function test_index_key_is_shared_by_values_the_rule_calls_equal(): void
    {
        self::assertSame(
            $this->subject->indexKey("CN=Admin, DC=Foo#'0101'B"),
            $this->subject->indexKey("cn=admin,dc=foo#'0101'B"),
        );
    }

    public function test_index_key_differs_when_only_one_side_carries_an_identifier(): void
    {
        self::assertNotSame(
            $this->subject->indexKey("cn=admin,dc=foo#'0101'B"),
            $this->subject->indexKey('cn=admin,dc=foo'),
        );
    }

    public function test_index_key_tells_an_empty_identifier_apart_from_none(): void
    {
        self::assertNotSame(
            $this->subject->indexKey("cn=admin,dc=foo#''B"),
            $this->subject->indexKey('cn=admin,dc=foo'),
        );
    }

    public function test_index_key_differs_when_the_identifiers_differ(): void
    {
        self::assertNotSame(
            $this->subject->indexKey("cn=admin,dc=foo#'0101'B"),
            $this->subject->indexKey("cn=admin,dc=foo#'1010'B"),
        );
    }

    public function test_index_key_is_null_when_a_part_comparator_is_not_indexable(): void
    {
        $subject = new NameAndOptionalUidComparator(uid: new IntegerComparator());

        self::assertNull($subject->indexKey('cn=admin,dc=foo'));
    }

    public function test_index_fragment_is_null_because_the_rule_matches_over_parsed_parts(): void
    {
        self::assertNull($this->subject->indexFragment('cn=admin'));
    }
}
