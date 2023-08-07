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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerDispatchHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPagingHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPagingUnsupportedHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerRootDseHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSearchHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerStartTlsHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerUnbindHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerWhoAmIHandler;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\ServerOptions;
use PhpSpec\ObjectBehavior;

class ServerProtocolHandlerFactorySpec extends ObjectBehavior
{
    public function let(
        HandlerFactoryInterface $handlerFactory,
        ServerQueue $queue,
    ): void {
        $this->beConstructedWith(
            $handlerFactory,
            new ServerOptions(),
            new RequestHistory(),
            $queue,
        );
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ServerProtocolHandlerFactory::class);
    }

    public function it_should_get_a_start_tls_hanlder(ServerQueue $queue): void
    {
        $this->get(Operations::extended(ExtendedRequest::OID_START_TLS), new ControlBag())
            ->shouldBeAnInstanceOf(ServerStartTlsHandler::class);
    }

    public function it_should_get_a_whoami_handler(ServerQueue $queue): void
    {
        $this->get(Operations::whoami(), new ControlBag())
            ->shouldBeAnInstanceOf(ServerWhoAmIHandler::class);
    }

    public function it_should_get_a_search_handler(HandlerFactoryInterface $handlerFactory): void
    {
        $handlerFactory->makeRequestHandler()
            ->willReturn(new GenericRequestHandler());

        $this->get(Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'), new ControlBag())
            ->shouldBeAnInstanceOf(ServerSearchHandler::class);
    }

    public function it_should_get_a_paging_handler_when_supported(
        HandlerFactoryInterface $handlerFactory,
        PagingHandlerInterface $pagingHandler
    ): void {
        $controls = new ControlBag(new PagingControl(10));

        $handlerFactory->makePagingHandler()
            ->shouldBeCalled()
            ->willReturn($pagingHandler);

        $this->get(Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'), $controls)->shouldBeAnInstanceOf(ServerPagingHandler::class);
    }

    public function it_should_get_a_paging_unsupported_handler_when_no_paging_handler_exists(HandlerFactoryInterface $handlerFactory): void
    {
        $controls = new ControlBag(new PagingControl(10));

        $handlerFactory->makePagingHandler()
            ->shouldBeCalled()
            ->willReturn(null);

        $handlerFactory->makeRequestHandler()
            ->willReturn(new GenericRequestHandler());

        $this->get(Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'), $controls)->shouldBeAnInstanceOf(ServerPagingUnsupportedHandler::class);
    }

    public function it_should_get_a_root_dse_handler(ServerQueue $queue): void
    {
        $this->get(Operations::read(''), new ControlBag())
            ->shouldBeAnInstanceOf(ServerRootDseHandler::class);
    }

    public function it_should_get_an_unbind_handler(ServerQueue $queue): void
    {
        $this->get(Operations::unbind(), new ControlBag())
            ->shouldBeAnInstanceOf(ServerUnbindHandler::class);
    }

    public function it_should_get_the_dispatch_handler_for_common_requests(HandlerFactoryInterface $handlerFactory,): void
    {
        $handlerFactory->makeRequestHandler()
            ->willReturn(new GenericRequestHandler());

        $this->get(Operations::add(Entry::fromArray('cn=foo')), new ControlBag())
            ->shouldBeAnInstanceOf(ServerDispatchHandler::class);
        $this->get(Operations::delete('cn=foo'), new ControlBag())
            ->shouldBeAnInstanceOf(ServerDispatchHandler::class);
        $this->get(Operations::compare('cn=foo', 'foo', 'bar'), new ControlBag())
            ->shouldBeAnInstanceOf(ServerDispatchHandler::class);
        $this->get(Operations::modify('cn=foo'), new ControlBag())
            ->shouldBeAnInstanceOf(ServerDispatchHandler::class);
        $this->get(Operations::move('cn=foo', 'foo=bar'), new ControlBag())
            ->shouldBeAnInstanceOf(ServerDispatchHandler::class);
        $this->get(Operations::rename('cn=foo', 'cn=foo'), new ControlBag())
            ->shouldBeAnInstanceOf(ServerDispatchHandler::class);
    }
}
