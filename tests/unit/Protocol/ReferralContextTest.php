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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Protocol\ReferralContext;
use PHPUnit\Framework\TestCase;

final class ReferralContextTest extends TestCase
{
    private ReferralContext $subject;

    protected function setUp(): void
    {
        $this->subject = new ReferralContext(new LdapUrl('foo'));
    }

    public function test_it_should_get_the_referrals(): void
    {
        self::assertEquals(
            [new LdapUrl('foo')],
            $this->subject->getReferrals(),
        );
    }

    public function test_it_should_check_if_it_has_a_specific_referral(): void
    {
        self::assertTrue($this->subject->hasReferral(new LdapUrl('Foo')));
        self::assertFalse($this->subject->hasReferral(new LdapUrl('bar')));
    }

    public function test_it_should_add_a_referral(): void
    {
        $this->subject->addReferral(new LdapUrl('bar'));

        self::assertEquals(
            [
                new LdapUrl('foo'),
                new LdapUrl('bar'),
            ],
            $this->subject->getReferrals(),
        );
    }

    public function test_it_should_get_the_referral_count(): void
    {
        self::assertCount(
            1,
            $this->subject
        );
    }
}
