<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\ProxyRequestHandler;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Socket\SocketServer;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapServerSpec extends ObjectBehavior
{
    function let(ServerRunnerInterface $serverRunner)
    {
        $this->beConstructedWith(['port' => 33389], $serverRunner);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LdapServer::class);
    }

    function it_should_run_the_server($serverRunner)
    {
        $serverRunner->run(Argument::type(SocketServer::class))->shouldBeCalled();

        $this->run();
    }

    function it_should_not_allow_a_request_handler_as_an_object()
    {
        $this->shouldThrow(RuntimeException::class)->during('__construct', [['request_handler' => new GenericRequestHandler()],]);
    }

    function it_should_only_allow_a_request_handler_implementing_request_handler_interface()
    {
        $this->shouldThrow(RuntimeException::class)->during('__construct', [['request_handler' => new Entry('foo')]]);
    }

    function it_should_allow_a_request_handler_as_a_string_implementing_request_handler_interface()
    {
        $this->shouldNotThrow(RuntimeException::class)->during('__construct', [['request_handler' => ProxyRequestHandler::class],]);
    }
}
