<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Tcp\TcpPool;
use PhpSpec\ObjectBehavior;

class ClientProtocolHandlerSpec extends ObjectBehavior
{
    function let(TcpPool $pool)
    {
        $this->beConstructedWith([], null, $pool);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ClientProtocolHandler::class);
    }

    function it_should_handle_a_bind_request()
    {

    }

    function it_should_handle_a_start_tls_request()
    {

    }

    function it_should_return_a_message_response()
    {

    }

    function it_should_not_throw_an_exception_if_specified()
    {

    }
}
