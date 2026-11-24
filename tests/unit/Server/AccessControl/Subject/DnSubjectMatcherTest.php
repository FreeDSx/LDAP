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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl\Subject;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Schema\AttributeTypeSpelling;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\AccessControl\Subject\DnSubjectMatcher;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DnSubjectMatcherTest extends TestCase
{
    private Dn $targetDn;

    private AttributeTypeSpelling $spelling;

    protected function setUp(): void
    {
        $this->targetDn = new Dn('dc=foo,dc=bar');
        $this->spelling = new AttributeTypeSpelling(SchemaResource::Core->load());
    }

    #[DataProvider('otherSpellingProvider')]
    public function test_a_dn_naming_a_type_another_way_matches_once_spelled_by_primary_names(string $dn): void
    {
        $subject = (new DnSubjectMatcher($dn))->spelledBy($this->spelling);

        self::assertTrue($subject->matches(
            BindToken::fromDn('cn=admin,dc=foo,dc=bar'),
            $this->targetDn,
        ));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function otherSpellingProvider(): iterable
    {
        yield 'an alias' => ['commonName=admin,dc=foo,dc=bar'];
        yield 'an OID' => ['2.5.4.3=admin,dc=foo,dc=bar'];
    }

    public function test_a_dn_spelled_by_primary_names_keeps_the_same_matcher(): void
    {
        $subject = new DnSubjectMatcher('CN=Admin,dc=foo,dc=bar');

        self::assertSame(
            $subject,
            $subject->spelledBy($this->spelling),
        );
    }

    public function test_it_should_match_when_username_equals_configured_dn(): void
    {
        $subject = new DnSubjectMatcher('cn=admin,dc=foo,dc=bar');

        self::assertTrue($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_match_case_insensitively(): void
    {
        $subject = new DnSubjectMatcher('cn=admin,dc=foo,dc=bar');

        self::assertTrue($subject->matches(
            BindToken::fromDn(
                'CN=Admin,DC=foo,DC=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_when_username_differs(): void
    {
        $subject = new DnSubjectMatcher('cn=admin,dc=foo,dc=bar');

        self::assertFalse($subject->matches(
            BindToken::fromDn(
                'cn=other,dc=foo,dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_for_anonymous_token(): void
    {
        $subject = new DnSubjectMatcher('cn=admin,dc=foo,dc=bar');

        self::assertFalse($subject->matches(
            new AnonToken(),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_for_anonymous_token_even_with_matching_dn(): void
    {
        $subject = new DnSubjectMatcher('cn=admin,dc=foo,dc=bar');

        self::assertFalse($subject->matches(
            new AnonToken('cn=admin,dc=foo,dc=bar'),
            $this->targetDn,
        ));
    }
}
