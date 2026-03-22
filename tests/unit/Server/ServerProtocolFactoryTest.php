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

use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerProtocolFactoryTest extends TestCase
{
    private ServerProtocolFactory $subject;

    private HandlerFactoryInterface&MockObject $mockHandlerFactory;

    private ServerAuthorization&MockObject $mockServerAuthorization;

    protected function setUp(): void
    {
        $this->mockHandlerFactory = $this->createMock(HandlerFactoryInterface::class);
        $this->mockServerAuthorization = $this->createMock(ServerAuthorization::class);

        $this->subject = new ServerProtocolFactory(
            $this->mockHandlerFactory,
            new ServerOptions(),
            $this->mockServerAuthorization,
        );
    }

    public function test_it_should_make_a_ServerProtocolInstance(): void
    {
        $mockSocket = $this->createMock(Socket::class);

        $this->mockHandlerFactory
            ->expects($this->once())
            ->method('makeRequestHandler')
            ->willReturn(new GenericRequestHandler());

        $this->subject->make($mockSocket);
    }

    public function test_it_includes_sasl_when_mechanisms_are_configured(): void
    {
        $mockSocket = $this->createMock(Socket::class);

        $this->mockHandlerFactory
            ->expects($this->once())
            ->method('makeRequestHandler')
            ->willReturn(new GenericRequestHandler());

        $subject = new ServerProtocolFactory(
            $this->mockHandlerFactory,
            (new ServerOptions())->setSaslMechanisms(ServerOptions::SASL_PLAIN),
            $this->mockServerAuthorization,
        );

        $subject->make($mockSocket);
    }
}
