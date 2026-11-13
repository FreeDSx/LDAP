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

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerProtocolFactoryTest extends TestCase
{
    private Container&MockObject $container;

    private ServerProtocolFactory $subject;

    protected function setUp(): void
    {
        $this->container = $this->createMock(Container::class);
        $this->subject = new ServerProtocolFactory($this->container);
    }

    public function test_it_resolves_the_handler_from_a_scope_opened_for_the_connection(): void
    {
        $socket = $this->createMock(Socket::class);
        $context = new ConnectionContext();
        $scope = $this->createMock(Container::class);
        $handler = $this->createMock(ServerProtocolHandler::class);

        $this->container
            ->expects($this->once())
            ->method('forConnection')
            ->with(
                $socket,
                $context,
            )
            ->willReturn($scope);
        $scope
            ->expects($this->once())
            ->method('get')
            ->with(ServerProtocolHandler::class)
            ->willReturn($handler);

        self::assertSame(
            $handler,
            $this->subject->make(
                $socket,
                $context,
            ),
        );
    }
}
