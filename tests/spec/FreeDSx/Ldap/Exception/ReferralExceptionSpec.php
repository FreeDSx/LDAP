<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Exception;

use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\ResultCode;
use PhpSpec\ObjectBehavior;

class ReferralExceptionSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo', new LdapUrl('foo'), new LdapUrl('bar'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ReferralException::class);
    }

    function it_should_extend_exception()
    {
        $this->shouldBeAnInstanceOf('\Exception');
    }

    function it_should_get_the_referrals()
    {
        $this->getReferrals()->shouldBeLike([
           new LdapUrl('foo'),
           new LdapUrl('bar')
        ]);
    }

    function it_should_set_the_message()
    {
        $this->getMessage()->shouldBeEqualTo('foo');
    }

    function it_should_have_a_code_of_the_referral_result_code()
    {
        $this->getCode()->shouldBeEqualTo(ResultCode::REFERRAL);
    }
}
