<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Server\ServerRunner;

use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Tcp\Socket;
use FreeDSx\Ldap\Tcp\SocketServer;
use PhpSpec\Exception\Example\SkippingException;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class PcntlServerRunnerSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith([]);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(PcntlServerRunner::class);
    }

    function it_should_implement_server_runner_interface()
    {
        $this->shouldImplement(ServerRunnerInterface::class);
    }

    function it_should_send_incoming_requests_to_the_server_protocol_handler(SocketServer $server, Socket $client)
    {
        if (!extension_loaded('pcntl')) {
            throw new SkippingException('The PCNTL extension is required for this spec.');
        }
        $server->accept()->willReturn($client, null);
        $client->read()->willReturn(false);
        $client->close()->willReturn(null);
        $client->isConnected()->willReturn(true);
        $client->write(Argument::any())->willReturn(null);
        $server->removeClient($client)->willReturn(null);

        $this->run($server);
    }
}
