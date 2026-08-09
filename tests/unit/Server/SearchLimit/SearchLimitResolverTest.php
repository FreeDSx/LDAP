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

namespace Tests\Unit\FreeDSx\Ldap\Server\SearchLimit;

use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitResolver;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitRule;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitRules;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class SearchLimitResolverTest extends TestCase
{
    private SearchLimits $default;

    protected function setUp(): void
    {
        $this->default = new SearchLimits(maxSearchSize: 1000);
    }

    public function test_it_returns_the_default_when_no_rule_matches(): void
    {
        $resolver = new SearchLimitResolver(
            new SearchLimitRules(),
            $this->default,
        );

        self::assertSame(
            $this->default,
            $resolver->resolve(new AnonToken()),
        );
    }

    public function test_it_returns_the_first_matching_rule_limits(): void
    {
        $authLimits = new SearchLimits(maxSearchSize: 50);
        $resolver = new SearchLimitResolver(
            (new SearchLimitRules())->withRules(
                SearchLimitRule::for(Subject::authenticated(), $authLimits),
            ),
            $this->default,
        );

        self::assertSame(
            $authLimits,
            $resolver->resolve($this->authenticatedToken()),
        );
    }

    public function test_a_rule_silent_on_paging_sessions_keeps_the_server_wide_cap(): void
    {
        $resolver = new SearchLimitResolver(
            (new SearchLimitRules())->withRules(
                SearchLimitRule::for(Subject::authenticated(), new SearchLimits(maxSearchSize: 50)),
            ),
            new SearchLimits(maxPagingSessions: 25),
        );

        self::assertSame(
            25,
            $resolver->resolve($this->authenticatedToken())->maxPagingSessions,
        );
    }

    public function test_a_rule_can_raise_the_paging_session_cap_for_an_identity(): void
    {
        $resolver = new SearchLimitResolver(
            (new SearchLimitRules())->withRules(
                SearchLimitRule::for(Subject::authenticated(), new SearchLimits(maxPagingSessions: 100)),
            ),
            new SearchLimits(maxPagingSessions: 25),
        );

        self::assertSame(
            100,
            $resolver->resolve($this->authenticatedToken())->maxPagingSessions,
        );
    }

    public function test_a_rule_can_lift_the_paging_session_cap_entirely(): void
    {
        $resolver = new SearchLimitResolver(
            (new SearchLimitRules())->withRules(
                SearchLimitRule::for(Subject::authenticated(), new SearchLimits(maxPagingSessions: 0)),
            ),
            new SearchLimits(maxPagingSessions: 25),
        );

        self::assertSame(
            0,
            $resolver->resolve($this->authenticatedToken())->maxPagingSessions,
        );
    }

    public function test_anonymous_falls_through_authenticated_rule_to_the_default(): void
    {
        $resolver = new SearchLimitResolver(
            (new SearchLimitRules())->withRules(
                SearchLimitRule::for(Subject::authenticated(), new SearchLimits(maxSearchSize: 50)),
            ),
            $this->default,
        );

        self::assertSame(
            $this->default,
            $resolver->resolve(new AnonToken()),
        );
    }

    public function test_first_matching_rule_wins(): void
    {
        $first = new SearchLimits(maxSearchSize: 10);
        $second = new SearchLimits(maxSearchSize: 20);
        $resolver = new SearchLimitResolver(
            (new SearchLimitRules())->withRules(
                SearchLimitRule::for(Subject::authenticated(), $first),
                SearchLimitRule::for(Subject::dn('cn=user,dc=foo,dc=bar'), $second),
            ),
            $this->default,
        );

        self::assertSame(
            $first,
            $resolver->resolve($this->authenticatedToken()),
        );
    }

    private function authenticatedToken(): BindToken
    {
        return BindToken::fromDn(
            'cn=user,dc=foo,dc=bar',
        );
    }
}
