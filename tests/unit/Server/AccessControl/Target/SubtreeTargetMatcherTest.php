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
use FreeDSx\Ldap\Server\AccessControl\Target\SubtreeTargetMatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SubtreeTargetMatcherTest extends TestCase
{
    private AttributeTypeSpelling $spelling;

    protected function setUp(): void
    {
        $this->spelling = new AttributeTypeSpelling(SchemaResource::Core->load());
    }

    #[DataProvider('otherSpellingProvider')]
    public function test_a_subtree_naming_a_type_another_way_matches_once_spelled_by_primary_names(string $dn): void
    {
        $subject = (new SubtreeTargetMatcher($dn))->spelledBy($this->spelling);

        self::assertTrue($subject->matches(new Dn('cn=alice,ou=people,dc=foo,dc=bar')));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function otherSpellingProvider(): iterable
    {
        yield 'an alias' => ['organizationalUnitName=people,dc=foo,dc=bar'];
        yield 'an OID' => ['2.5.4.11=people,dc=foo,dc=bar'];
    }

    public function test_a_subtree_spelled_by_primary_names_keeps_the_same_matcher(): void
    {
        $subject = new SubtreeTargetMatcher('ou=people,dc=foo,dc=bar');

        self::assertSame(
            $subject,
            $subject->spelledBy($this->spelling),
        );
    }

    public function test_it_should_match_descendant_dn(): void
    {
        $subject = new SubtreeTargetMatcher('dc=foo,dc=bar');

        self::assertTrue($subject->matches(new Dn('cn=admin,dc=foo,dc=bar')));
    }

    public function test_it_should_match_deeply_nested_descendant(): void
    {
        $subject = new SubtreeTargetMatcher('dc=foo,dc=bar');

        self::assertTrue($subject->matches(new Dn('uid=user,ou=people,dc=foo,dc=bar')));
    }

    public function test_it_should_match_root_dn_of_subtree_itself(): void
    {
        $subject = new SubtreeTargetMatcher('dc=foo,dc=bar');

        // isDescendantOf uses inclusive subtree semantics — the root matches itself.
        self::assertTrue($subject->matches(new Dn('dc=foo,dc=bar')));
    }

    public function test_it_should_not_match_sibling_subtree(): void
    {
        $subject = new SubtreeTargetMatcher('dc=foo,dc=bar');

        self::assertFalse($subject->matches(new Dn('cn=admin,dc=other,dc=bar')));
    }
}
