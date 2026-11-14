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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue\Budget;

use FreeDSx\Ldap\Protocol\Queue\Budget\IdentityShare;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class IdentityShareTest extends TestCase
{
    private const LIMIT = 25_000;

    private ServerAuthorization $authorization;

    private IdentityShare $subject;

    protected function setUp(): void
    {
        $this->authorization = new ServerAuthorization(TestServerOptions::defaults());
        $this->subject = new IdentityShare(
            $this->authorization,
            self::LIMIT,
        );
    }

    public function test_a_session_that_has_not_bound_has_the_anonymous_share(): void
    {
        self::assertSame(
            ['', self::LIMIT],
            [$this->subject->current()->key, $this->subject->current()->limit],
        );
    }

    public function test_an_unauthenticated_session_shares_the_anonymous_share(): void
    {
        $this->authorization->setToken(new AnonToken('cn=someone,dc=foo,dc=bar'));

        self::assertSame(
            '',
            $this->subject->current()->key,
        );
    }

    public function test_a_bound_identity_has_one_share_however_its_dn_is_spelled(): void
    {
        $this->authorization->setToken(BindToken::fromDn('CN=User, DC=Foo,DC=Bar'));
        $spelled = $this->subject->current()->key;
        $this->authorization->setToken(BindToken::fromDn('cn=user,dc=foo,dc=bar'));

        self::assertSame(
            ['dn:cn=user,dc=foo,dc=bar', 'dn:cn=user,dc=foo,dc=bar'],
            [$spelled, $this->subject->current()->key],
        );
    }

    public function test_a_bind_name_that_is_not_a_dn_has_one_share_whatever_its_case(): void
    {
        $this->authorization->setToken(BindToken::fromDn('User@Foo.Bar'));

        self::assertSame(
            'dn:user@foo.bar',
            $this->subject->current()->key,
        );
    }

    public function test_the_share_follows_a_rebind(): void
    {
        $this->authorization->setToken(BindToken::fromDn('cn=user,dc=foo,dc=bar'));
        $first = $this->subject->current()->key;
        $this->authorization->setToken(BindToken::fromDn('cn=other,dc=foo,dc=bar'));

        self::assertSame(
            ['dn:cn=user,dc=foo,dc=bar', 'dn:cn=other,dc=foo,dc=bar'],
            [$first, $this->subject->current()->key],
        );
    }

    public function test_the_share_is_kept_while_the_bound_identity_is_unchanged(): void
    {
        self::assertSame(
            $this->subject->current(),
            $this->subject->current(),
        );
    }

    public function test_an_identity_may_hold_a_quarter_of_the_limit(): void
    {
        self::assertSame(
            25_000,
            IdentityShare::limitOf(
                100_000,
                10_000,
            ),
        );
    }

    public function test_an_identity_may_hold_at_least_what_the_largest_request_allowed_holds(): void
    {
        self::assertSame(
            60_000,
            IdentityShare::limitOf(
                100_000,
                60_000,
            ),
        );
    }

    public function test_an_identity_may_hold_no_more_than_the_whole_limit(): void
    {
        self::assertSame(
            100_000,
            IdentityShare::limitOf(
                100_000,
                PHP_INT_MAX,
            ),
        );
    }
}
