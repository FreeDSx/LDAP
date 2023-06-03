<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Server\ChildProcess;
use FreeDSx\Socket\Socket;
use PhpSpec\ObjectBehavior;

class ChildProcessSpec extends ObjectBehavior
{
    public function let(Socket $socket): void
    {
        $this->beConstructedWith(9001, $socket);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ChildProcess::class);
    }

    public function it_should_get_the_pid(): void
    {
        $this->getPid()->shouldBeEqualTo(9001);
    }

    public function it_should_get_the_socket(): void
    {
        $this->getSocket()->shouldBeAnInstanceOf(Socket::class);
    }

    public function it_should_close_the_socket(Socket $socket): void
    {
        $socket->close()->shouldBeCalled();

        $this->closeSocket();
    }
}
