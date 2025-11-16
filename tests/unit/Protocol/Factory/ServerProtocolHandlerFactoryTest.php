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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operations;
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
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerProtocolHandlerFactoryTest extends TestCase
{
    private ServerProtocolHandlerFactory $subject;

    private ServerQueue&MockObject $mockQueue;

    private HandlerFactoryInterface&MockObject $mockHandlerFactory;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockHandlerFactory = $this->createMock(HandlerFactoryInterface::class);

        $this->subject = new ServerProtocolHandlerFactory(
            $this->mockHandlerFactory,
            new ServerOptions(),
            new RequestHistory(),
            $this->mockQueue
        );
    }

    public function test_it_should_get_a_start_tls_hanlder(): void
    {
        self::assertInstanceof(
            ServerStartTlsHandler::class,
            $this->subject->get(
                Operations::extended(ExtendedRequest::OID_START_TLS),
                new ControlBag(),
            ),
        );
    }

    public function test_it_should_get_a_whoami_handler(): void
    {
        self::assertInstanceof(
            ServerWhoAmIHandler::class,
            $this->subject->get(
                Operations::whoami(),
                new ControlBag(),
            )
        );
    }

    public function test_it_should_get_a_search_handler(): void
    {
        $this->mockHandlerFactory
            ->expects(self::once())->method('makeRequestHandler')
            ->willReturn(new GenericRequestHandler());

        self::assertInstanceof(
            ServerSearchHandler::class,
            $this->subject->get(
                Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'),
                new ControlBag(),
            )
        );
    }

    public function test_it_should_get_a_paging_handler_when_supported(): void
    {
        $controls = new ControlBag(new PagingControl(10));

        $mockPagingHandler = $this->createMock(PagingHandlerInterface::class);

        $this->mockHandlerFactory
            ->expects(self::once())
            ->method('makePagingHandler')
            ->willReturn($mockPagingHandler);

        self::assertInstanceOf(
            ServerPagingHandler::class,
            $this->subject->get(
                Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'),
                $controls,
            )
        );
    }

    public function test_it_should_get_a_paging_unsupported_handler_when_no_paging_handler_exists(): void
    {
        $controls = new ControlBag(new PagingControl(10));

        $this->mockHandlerFactory
            ->expects(self::once())
            ->method('makePagingHandler')
            ->willReturn(null);

        $this->mockHandlerFactory
            ->expects(self::once())
            ->method('makeRequestHandler')
            ->willReturn(new GenericRequestHandler());

        self::assertInstanceOf(
            ServerPagingUnsupportedHandler::class,
            $this->subject->get(
                Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'),
                $controls
            )
        );
    }

    public function test_it_should_get_a_root_dse_handler(): void
    {
        self::assertInstanceOf(
            ServerRootDseHandler::class,
            $this->subject->get(
                Operations::read(''),
                new ControlBag()
            ),
        );
    }

    public function test_it_should_get_an_unbind_handler(): void
    {
        self::assertInstanceOf(
            ServerUnbindHandler::class,
            $this->subject->get(
                Operations::unbind(),
                new ControlBag()
            )
        );
    }

    public function test_it_should_get_the_dispatch_handler_for_common_requests(): void
    {
        $this->mockHandlerFactory
            ->method('makeRequestHandler')
            ->willReturn(new GenericRequestHandler());

        self::assertInstanceOf(
            ServerDispatchHandler::class,
            $this->subject->get(Operations::delete('cn=foo'), new ControlBag())
        );
        self::assertInstanceOf(
            ServerDispatchHandler::class,
            $this->subject->get(Operations::add(Entry::fromArray('cn=foo')), new ControlBag())
        );
        self::assertInstanceOf(
            ServerDispatchHandler::class,
            $this->subject->get(Operations::compare('cn=foo', 'foo', 'bar'), new ControlBag())
        );
        self::assertInstanceOf(
            ServerDispatchHandler::class,
            $this->subject->get(Operations::modify('cn=foo'), new ControlBag()),
        );
        self::assertInstanceOf(
            ServerDispatchHandler::class,
            $this->subject->get(Operations::move('cn=foo', 'foo=bar'), new ControlBag()),
        );
        self::assertInstanceOf(
            ServerDispatchHandler::class,
            $this->subject->get(Operations::rename('cn=foo', 'cn=foo'), new ControlBag()),
        );
    }
}
