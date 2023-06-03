<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PhpSpec\ObjectBehavior;

class RequestContextSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(new ControlBag(), new AnonToken(null));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(RequestContext::class);
    }

    public function it_should_get_the_token(): void
    {
        $this->token()->shouldBeAnInstanceOf(new AnonToken(null));
    }

    public function it_should_get_the_controls(): void
    {
        $this->controls()->shouldBeAnInstanceOf(new ControlBag());
    }
}
