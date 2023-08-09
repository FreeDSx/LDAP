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

namespace spec\FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Protocol\Factory\ServerBindHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerAnonBindHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerBindHandler;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use PhpSpec\ObjectBehavior;

class ServerBindHandlerFactorySpec extends ObjectBehavior
{
    public function let(
        ServerQueue $queue,
        HandlerFactoryInterface $handlerFactory,
    ): void {
        $this->beConstructedWith(
            $queue,
            $handlerFactory,
        );
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ServerBindHandlerFactory::class);
    }

    public function it_should_get_an_anon_bind_handler(): void
    {
        $this->get(new AnonBindRequest())
            ->shouldBeAnInstanceOf(ServerAnonBindHandler::class);
    }

    public function it_should_get_a_simple_bind_handler(HandlerFactoryInterface $handlerFactory): void
    {
        $handlerFactory
            ->makeRequestHandler()
            ->willReturn(new GenericRequestHandler());

        $this->get(new SimpleBindRequest('foo', 'bar'))
            ->shouldBeAnInstanceOf(ServerBindHandler::class);
    }

    public function it_should_throw_an_exception_on_an_unknown_bind_type(BindRequest $request): void
    {
        $this->shouldThrow(OperationException::class)
            ->during('get', [$request]);
    }
}
