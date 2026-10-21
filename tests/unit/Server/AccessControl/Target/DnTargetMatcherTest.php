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
use FreeDSx\Ldap\Server\AccessControl\Target\DnTargetMatcher;
use PHPUnit\Framework\TestCase;

final class DnTargetMatcherTest extends TestCase
{
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
