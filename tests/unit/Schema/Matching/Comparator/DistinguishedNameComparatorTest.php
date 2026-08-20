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

use FreeDSx\Ldap\Schema\Matching\Comparator\DistinguishedNameComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class DistinguishedNameComparatorTest extends TestCase
{
    private DistinguishedNameComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new DistinguishedNameComparator();
    }

    public function test_equals_same_dn(): void
    {
        $result = $this->subject->equals(
            'cn=foo,dc=example,dc=com',
            'cn=foo,dc=example,dc=com',
        );

        self::assertTrue($result);
    }

    public function test_equals_case_insensitive(): void
    {
        $result = $this->subject->equals(
            'CN=Foo,DC=Example,DC=Com',
            'cn=foo,dc=example,dc=com',
        );

        self::assertTrue($result);
    }

    public function test_equals_ignores_insignificant_whitespace(): void
    {
        $result = $this->subject->equals(
            'cn=John  Smith , dc=example , dc=com',
            'cn=john smith,dc=example,dc=com',
        );

        self::assertTrue($result);
    }

    public function test_equals_ignores_multivalued_rdn_order(): void
    {
        $result = $this->subject->equals(
            'cn=a+uid=b,dc=com',
            'uid=b+cn=a,dc=com',
        );

        self::assertTrue($result);
    }

    public function test_equals_different_dn(): void
    {
        $result = $this->subject->equals(
            'cn=foo,dc=example,dc=com',
            'cn=bar,dc=example,dc=com',
        );

        self::assertFalse($result);
    }

    public function test_compare_equal(): void
    {
        $result = $this->subject->compare(
            'cn=foo,dc=example,dc=com',
            'CN=foo,DC=example,DC=com',
        );

        self::assertSame(0, $result);
    }

    public function test_substring_always_returns_false(): void
    {
        $result = $this->subject->substringMatches(
            'cn=foo,dc=example,dc=com',
            new SubstringAssertion(initial: 'cn=foo'),
        );

        self::assertFalse($result);
    }

    public function test_index_key_is_shared_by_dns_the_rule_calls_equal(): void
    {
        self::assertSame(
            $this->subject->indexKey('CN=John  Smith , DC=Example , DC=Com'),
            $this->subject->indexKey('cn=john smith,dc=example,dc=com'),
        );
    }

    public function test_index_key_is_shared_regardless_of_multivalued_rdn_order(): void
    {
        self::assertSame(
            $this->subject->indexKey('cn=a+uid=b,dc=com'),
            $this->subject->indexKey('uid=b+cn=a,dc=com'),
        );
    }

    public function test_index_key_differs_for_dns_naming_different_entries(): void
    {
        self::assertNotSame(
            $this->subject->indexKey('cn=foo,dc=example,dc=com'),
            $this->subject->indexKey('cn=bar,dc=example,dc=com'),
        );
    }

    public function test_index_fragment_is_null_because_the_rule_matches_over_parsed_rdns(): void
    {
        self::assertNull($this->subject->indexFragment('cn=foo'));
    }
}
