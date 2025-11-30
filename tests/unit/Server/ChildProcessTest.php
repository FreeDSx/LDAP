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

namespace Tests\Unit\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Server\ChildProcess;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ChildProcessTest extends TestCase
{
    private ChildProcess $subject;

    private Socket&MockObject $mockSocket;

    protected function setUp(): void
    {
        $this->mockSocket = $this->createMock(Socket::class);

        $this->subject = new ChildProcess(
            9001,
            $this->mockSocket,
        );
    }

    public function test_it_should_get_the_pid(): void
    {
        self::assertSame(
            9001,
            $this->subject->getPid(),
        );
    }

    public function test_it_should_get_the_socket(): void
    {
        self::assertSame(
            $this->mockSocket,
            $this->subject->getSocket(),
        );
    }

    public function test_it_should_close_the_socket(): void
    {
        $this->mockSocket
            ->expects(self::once())
            ->method('close');

        $this->subject->closeSocket();
    }
}
