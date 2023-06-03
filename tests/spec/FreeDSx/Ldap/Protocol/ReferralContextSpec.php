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

namespace spec\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Protocol\ReferralContext;
use PhpSpec\ObjectBehavior;

class ReferralContextSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(new LdapUrl('foo'));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ReferralContext::class);
    }

    public function it_should_get_the_referrals(): void
    {
        $this->getReferrals()->shouldBeLike([new LdapUrl('foo')]);
    }

    public function it_should_check_if_it_has_a_specific_referral(): void
    {
        $this->hasReferral(new LdapUrl('Foo'))->shouldBeLike(true);
        $this->hasReferral(new LdapUrl('bar'))->shouldBeLike(false);
    }

    public function it_should_add_a_referral(): void
    {
        $this->addReferral(new LdapUrl('bar'));

        $this->getReferrals()->shouldBeLike([
            new LdapUrl('foo'),
            new LdapUrl('bar')
        ]);
    }

    public function it_should_get_the_referral_count(): void
    {
        $this->count()->shouldBeEqualTo(1);
    }
}
