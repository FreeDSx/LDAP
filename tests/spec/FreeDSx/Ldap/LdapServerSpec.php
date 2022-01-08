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
use FreeDSx\Socket\SocketServer;
use PhpSpec\Exception\Example\SkippingException;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapServerSpec extends ObjectBehavior
{
    public function let(ServerRunnerInterface $serverRunner)
    {
        $this->beConstructedWith(['port' => 33389], $serverRunner);
    }

    public function it_is_initializable()
    {
        if (!extension_loaded('pcntl')) {
            throw new SkippingException('The PCNTL extension is required for this spec.');
        }

        $this->shouldHaveType(LdapServer::class);
    }

    public function it_should_run_the_server($serverRunner)
    {
        if (!extension_loaded('pcntl')) {
            throw new SkippingException('The PCNTL extension is required for this spec.');
        }

        $serverRunner->run(Argument::type(SocketServer::class))->shouldBeCalled();

        $this->run();
    }
}
