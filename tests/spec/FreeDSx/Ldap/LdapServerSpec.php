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

use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Tcp\SocketServer;
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
}
