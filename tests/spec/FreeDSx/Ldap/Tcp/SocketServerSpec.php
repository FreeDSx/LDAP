<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Tcp;

use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Tcp\SocketServer;
use PhpSpec\ObjectBehavior;

class SocketServerSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedThrough('bind', ['0.0.0.0', 33389]);
    }

    function letGo()
    {
        @$this->close();
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SocketServer::class);
    }

    function it_should_throw_a_connection_exception_if_it_cannot_listen_on_the_ip_and_port()
    {
        $this->beConstructedWith([]);

        $this->shouldThrow(ConnectionException::class)->duringListen('1.2.3.4', 389);
    }

    function it_should_return_null_if_there_is_no_client_on_accept()
    {
        $this->accept(0)->shouldBeNull();
    }
}
