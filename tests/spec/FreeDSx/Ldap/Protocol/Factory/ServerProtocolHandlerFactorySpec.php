<?php

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
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
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
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHistory;
use PhpSpec\ObjectBehavior;

class ServerProtocolHandlerFactorySpec extends ObjectBehavior
{
    public function let(HandlerFactoryInterface $handlerFactory)
    {
        $this->beConstructedWith(
            $handlerFactory,
            new RequestHistory()
        );
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(ServerProtocolHandlerFactory::class);
    }

    public function it_should_get_a_start_tls_hanlder()
    {
        $this->get(Operations::extended(ExtendedRequest::OID_START_TLS), new ControlBag())->shouldBeLike(new ServerStartTlsHandler());
    }

    public function it_should_get_a_whoami_handler()
    {
        $this->get(Operations::whoami(), new ControlBag())->shouldBeLike(new ServerWhoAmIHandler());
    }

    public function it_should_get_a_search_handler()
    {
        $this->get(Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'), new ControlBag())->shouldBeLike(new ServerSearchHandler());
    }

    public function it_should_get_a_paging_handler_when_supported(
        HandlerFactoryInterface $handlerFactory,
        PagingHandlerInterface $pagingHandler
    ) {
        $controls = new ControlBag(new PagingControl(10));

        $handlerFactory->makePagingHandler()
            ->shouldBeCalled()
            ->willReturn($pagingHandler);

        $this->get(Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'), $controls)->shouldBeAnInstanceOf(ServerPagingHandler::class);
    }

    public function it_should_get_a_paging_unsupported_handler_when_no_paging_handler_exists(HandlerFactoryInterface $handlerFactory)
    {
        $controls = new ControlBag(new PagingControl(10));

        $handlerFactory->makePagingHandler()
            ->shouldBeCalled()
            ->willReturn(null);

        $this->get(Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'), $controls)->shouldBeAnInstanceOf(ServerPagingUnsupportedHandler::class);
    }

    public function it_should_get_a_root_dse_handler()
    {
        $this->get(Operations::read(''), new ControlBag())->shouldBeLike(new ServerRootDseHandler());
    }

    public function it_should_get_an_unbind_handler()
    {
        $this->get(Operations::unbind(), new ControlBag())->shouldBeLike(new ServerUnbindHandler());
    }

    public function it_should_get_the_dispatch_handler_for_common_requests()
    {
        $this->get(Operations::add(Entry::fromArray('cn=foo')), new ControlBag())->shouldBeLike(new ServerDispatchHandler());
        $this->get(Operations::delete('cn=foo'), new ControlBag())->shouldBeLike(new ServerDispatchHandler());
        $this->get(Operations::compare('cn=foo', 'foo', 'bar'), new ControlBag())->shouldBeLike(new ServerDispatchHandler());
        $this->get(Operations::modify('cn=foo'), new ControlBag())->shouldBeLike(new ServerDispatchHandler());
        $this->get(Operations::move('cn=foo', 'foo=bar'), new ControlBag())->shouldBeLike(new ServerDispatchHandler());
        $this->get(Operations::rename('cn=foo', 'cn=foo'), new ControlBag())->shouldBeLike(new ServerDispatchHandler());
    }
}
