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
}
