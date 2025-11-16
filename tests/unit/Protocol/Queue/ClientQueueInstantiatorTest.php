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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketPool;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ClientQueueInstantiatorTest extends TestCase
{
    private ClientQueueInstantiator $subject;

    private SocketPool&MockObject $mockPool;

    private Socket&MockObject $mockSocket;

    protected function setUp(): void
    {
        $this->mockPool = $this->createMock(SocketPool::class);
        $this->mockSocket = $this->createMock(Socket::class);

        $this->subject = new ClientQueueInstantiator($this->mockPool);
    }

    public function test_it_should_return_false_if_not_instantiated_for_isConnectedAndInstantiated(): void
    {
        self::assertFalse($this->subject->isInstantiatedAndConnected());
    }

    public function test_it_should_return_false_if_instantiated_but_not_connected_for_isConnectedAndInstantiated(): void
    {
        $this->mockPool
            ->method('connect')
            ->willReturn($this->mockSocket);
        $this->mockPool
            ->method('connect')
            ->willReturn($this->mockSocket);

        $this->mockSocket
            ->method('isConnected')
            ->willReturn(false);

        $this->subject->make();

        self::assertFalse($this->subject->isInstantiatedAndConnected());
    }

    public function test_it_should_return_true_if_instantiated_and_connected_for_isConnectedAndInstantiated(): void
    {
        $this->mockPool
            ->method('connect')
            ->willReturn($this->mockSocket);

        $this->mockSocket
            ->method('isConnected')
            ->willReturn(true);

        $this->subject->make();

        self::assertTrue($this->subject->isInstantiatedAndConnected());
    }

    public function test_it_should_return_an_instantiated_socket_on_make(): void {
        $this->mockPool
            ->method('connect')
            ->willReturn($this->mockSocket);
        $this->mockSocket
            ->method('isConnected')
            ->willReturn(true);

        $result = $this->subject->make();

        self::assertTrue($result->isConnected());
    }

    public function test_it_should_return_the_same_queue_when_it_was_already_instantiated(): void
    {
        $this->mockPool
            ->method('connect')
            ->willReturn($this->mockSocket);

        self::assertSame(
            $this->subject->make(),
            $this->subject->make(),
        );
    }
}
