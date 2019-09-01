<?php
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
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Protocol\ReferralContext;
use PhpSpec\ObjectBehavior;

class ReferralContextSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new LdapUrl('foo'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ReferralContext::class);
    }

    function it_should_get_the_referrals()
    {
        $this->getReferrals()->shouldBeLike([new LdapUrl('foo')]);
    }

    function it_should_check_if_it_has_a_specific_referral()
    {
        $this->hasReferral(new LdapUrl('Foo'))->shouldBeLike(true);
        $this->hasReferral(new LdapUrl('bar'))->shouldBeLike(false);
    }

    function it_should_add_a_referral()
    {
        $this->addReferral(new LdapUrl('bar'));

        $this->getReferrals()->shouldBeLike([
            new LdapUrl('foo'),
            new LdapUrl('bar')
        ]);
    }

    function it_should_get_the_referral_count()
    {
        $this->count()->shouldBeEqualTo(1);
    }
}
