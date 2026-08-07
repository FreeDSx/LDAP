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

namespace Tests\Unit\FreeDSx\Ldap\Server\Process;

use FreeDSx\Ldap\Server\Process\ChildChannel;
use FreeDSx\Ldap\Server\Process\ChildProcess;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Process\FakeChannelMessageFactory;

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

    public function test_it_should_release_the_socket_without_shutting_it_down(): void
    {
        $this->mockSocket
            ->expects(self::once())
            ->method('close')
            ->with(false);

        $this->subject->releaseSocket();
    }

    public function test_the_channel_is_null_by_default(): void
    {
        self::assertNull($this->subject->getChannel());
    }

    public function test_it_should_get_the_channel_when_present(): void
    {
        if (str_starts_with(strtoupper(PHP_OS), 'WIN')) {
            self::markTestSkipped('UNIX socket pairs are unavailable on Windows; the channel is Linux/PCNTL-only.');
        }

        $channel = ChildChannel::create(new FakeChannelMessageFactory());

        $subject = new ChildProcess(
            9002,
            $this->mockSocket,
            $channel,
        );

        self::assertSame(
            $channel,
            $subject->getChannel(),
        );
    }
}
