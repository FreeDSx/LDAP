<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Server\Token;

use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PhpSpec\ObjectBehavior;

class AnonTokenSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(AnonToken::class);
    }

    function it_should_implement_token_interface()
    {
        $this->shouldImplement(TokenInterface::class);
    }

    function it_should_get_the_username()
    {
        $this->getUsername()->shouldBeEqualTo('foo');
    }

    function it_should_get_a_null_password()
    {
        $this->getPassword()->shouldBeNull();
    }

    function it_should_get_the_version()
    {
        $this->getVersion()->shouldBeEqualTo(3);
    }
}
