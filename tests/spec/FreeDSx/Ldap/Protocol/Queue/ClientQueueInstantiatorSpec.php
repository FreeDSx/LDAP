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

namespace spec\FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketPool;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientQueueInstantiatorSpec extends ObjectBehavior
{
    public function let(SocketPool $socketPool): void
    {
        $this->beConstructedWith($socketPool);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ClientQueueInstantiator::class);
    }

    public function it_should_return_false_if_not_instantiated_for_isConnectedAndInstantiated(): void
    {
        $this->isInstantiatedAndConnected()
            ->shouldBe(false);
    }

    public function it_should_return_false_if_instantiated_but_not_connected_for_isConnectedAndInstantiated(
        SocketPool $socketPool,
        Socket $socket,
    ): void {
        $socketPool->connect(Argument::any())
            ->willReturn($socket);

        $socket->isConnected()
            ->willReturn(false);

        $this->make();

        $this->isInstantiatedAndConnected()
            ->shouldBe(false);
    }

    public function it_should_return_true_if_instantiated_and_connected_for_isConnectedAndInstantiated(
        SocketPool $socketPool,
        Socket $socket,
    ): void {
        $socketPool->connect(Argument::any())
            ->willReturn($socket);

        $socket->isConnected()
            ->willReturn(true);

        $this->make();

        $this->isInstantiatedAndConnected()
            ->shouldBe(true);
    }

    public function it_should_return_an_instantiated_socket_on_make(
        SocketPool $socketPool,
        Socket $socket,
    ): void {
        $socketPool->connect(Argument::any())
            ->willReturn($socket);

        $this->make()
            ->shouldBeAnInstanceOf(ClientQueue::class);
    }

    public function it_should_return_the_same_queue_when_it_was_already_instantiated(
        SocketPool $socketPool,
        Socket $socket,
    ): void {
        $socketPool->connect(Argument::any())
            ->willReturn($socket);

        $queue = $this->make();

        $this->make()
            ->shouldBe($queue->getWrappedObject());
    }
}
