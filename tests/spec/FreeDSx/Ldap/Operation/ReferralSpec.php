<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation;

use FreeDSx\Ldap\Operation\Referral;
use PhpSpec\ObjectBehavior;

class ReferralSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Referral::class);
    }

    function it_should_have_a_string_representation()
    {
        $this->__toString()->shouldBeEqualTo('foo');
    }
}
