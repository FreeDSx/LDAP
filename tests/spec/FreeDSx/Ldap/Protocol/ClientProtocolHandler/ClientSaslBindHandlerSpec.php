<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSaslBindHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use PhpSpec\ObjectBehavior;

class ClientSaslBindHandlerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ClientSaslBindHandler::class);
    }

    function it_should_implement_RequestHandlerInterface()
    {
        $this->shouldBeAnInstanceOf(RequestHandlerInterface::class);
    }

    function it_should_handle_a_sasl_bind_request()
    {

    }
}
