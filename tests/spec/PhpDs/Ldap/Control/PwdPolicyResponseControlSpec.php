<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Control;

use PhpDs\Ldap\Control\PwdPolicyResponseControl;
use PhpSpec\ObjectBehavior;

class PwdPolicyResponseControlSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1, 2, 3);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(PwdPolicyResponseControl::class);
    }

    function it_should_get_the_error()
    {
        $this->getError()->shouldBeEqualTo(3);
    }

    function it_should_get_the_time_before_expiration()
    {
        $this->getTimeBeforeExpiration()->shouldBeEqualTo(1);
    }

    function it_should_get_the_grace_attempts_remaining()
    {
        $this->getGraceAttemptsRemaining()->shouldBeEqualTo(2);
    }

    function it_should_be_constructed_from_asn1()
    {
    }
}
