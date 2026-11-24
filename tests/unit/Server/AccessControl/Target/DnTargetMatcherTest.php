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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl\Target;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Schema\AttributeTypeSpelling;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\AccessControl\Target\DnTargetMatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DnTargetMatcherTest extends TestCase
{
    private AttributeTypeSpelling $spelling;

    protected function setUp(): void
    {
        $this->spelling = new AttributeTypeSpelling(SchemaResource::Core->load());
    }

    #[DataProvider('otherSpellingProvider')]
    public function test_a_dn_naming_a_type_another_way_matches_once_spelled_by_primary_names(string $dn): void
    {
        $subject = (new DnTargetMatcher($dn))->spelledBy($this->spelling);

        self::assertTrue($subject->matches(new Dn('cn=foo,dc=bar')));
        self::assertSame(
            'cn=foo,dc=bar',
            $subject->normalizedDn(),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function otherSpellingProvider(): iterable
    {
        yield 'an alias' => ['commonName=foo,dc=bar'];
        yield 'an OID' => ['2.5.4.3=foo,dc=bar'];
    }

    public function test_a_dn_spelled_by_primary_names_keeps_the_same_matcher(): void
    {
        $subject = new DnTargetMatcher('CN=Foo,dc=bar');

        self::assertSame(
            $subject,
            $subject->spelledBy($this->spelling),
        );
    }

    public function test_it_should_match_exact_dn(): void
    {
        $subject = new DnTargetMatcher('cn=foo,dc=bar');

        self::assertTrue($subject->matches(new Dn('cn=foo,dc=bar')));
    }

    public function test_it_should_match_case_insensitively(): void
    {
        $subject = new DnTargetMatcher('cn=foo,dc=bar');

        self::assertTrue($subject->matches(new Dn('CN=Foo,DC=bar')));
    }

    public function test_it_should_not_match_different_dn(): void
    {
        $subject = new DnTargetMatcher('cn=foo,dc=bar');

        self::assertFalse($subject->matches(new Dn('cn=other,dc=bar')));
    }

    public function test_it_exposes_the_canonical_form_of_the_dn_it_matches(): void
    {
        $subject = new DnTargetMatcher('CN=Foo,DC=bar');

        self::assertSame(
            (new Dn('cn=foo,dc=bar'))->normalizedString(),
            $subject->normalizedDn(),
        );
    }
}
