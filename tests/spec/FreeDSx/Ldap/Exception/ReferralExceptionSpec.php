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

namespace spec\FreeDSx\Ldap\Exception;

use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\ResultCode;
use PhpSpec\ObjectBehavior;

class ReferralExceptionSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('foo', new LdapUrl('foo'), new LdapUrl('bar'));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ReferralException::class);
    }

    public function it_should_extend_exception(): void
    {
        $this->shouldBeAnInstanceOf('\Exception');
    }

    public function it_should_get_the_referrals(): void
    {
        $this->getReferrals()->shouldBeLike([
           new LdapUrl('foo'),
           new LdapUrl('bar')
        ]);
    }

    public function it_should_set_the_message(): void
    {
        $this->getMessage()->shouldBeEqualTo('foo');
    }

    public function it_should_have_a_code_of_the_referral_result_code(): void
    {
        $this->getCode()->shouldBeEqualTo(ResultCode::REFERRAL);
    }
}
