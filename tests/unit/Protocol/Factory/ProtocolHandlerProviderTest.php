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

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Factory\HandlerContext;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;
use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerFactoryMap;
use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerProvider;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ConnectionControl;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerDispatchHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPagingHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPasswordModifyHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerProtocolHandlerInterface;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerRootDseHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSearchHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerStartTlsHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSubschemaHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerUnbindHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerUnsupportedExtendedHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerWhoAmIHandler;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ProtocolHandlerProviderTest extends TestCase
{
    private ProtocolHandlerProvider $subject;

    protected function setUp(): void
    {
        $container = Container::forServer(new ServerOptions());

        $this->subject = new ProtocolHandlerProvider(
            routeResolver: $container->get(ServerProtocolHandlerFactory::class),
            factories: $container->get(ProtocolHandlerFactoryMap::class),
            context: $this->handlerContext(),
        );
    }

    public function test_it_should_get_a_password_modify_handler(): void
    {
        self::assertInstanceOf(
            ServerPasswordModifyHandler::class,
            $this->subject->get(
                Operations::extended(ExtendedRequest::OID_PWD_MODIFY),
                new ControlBag(),
            ),
        );
    }

    public function test_it_should_get_a_start_tls_handler(): void
    {
        self::assertInstanceOf(
            ServerStartTlsHandler::class,
            $this->subject->get(
                Operations::extended(ExtendedRequest::OID_START_TLS),
                new ControlBag(),
            ),
        );
    }

    public function test_it_should_get_a_whoami_handler(): void
    {
        self::assertInstanceOf(
            ServerWhoAmIHandler::class,
            $this->subject->get(
                Operations::whoami(),
                new ControlBag(),
            ),
        );
    }

    public function test_it_should_get_a_search_handler(): void
    {
        self::assertInstanceOf(
            ServerSearchHandler::class,
            $this->subject->get(
                Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'),
                new ControlBag(),
            ),
        );
    }

    public function test_it_should_get_a_paging_handler_when_a_paging_control_is_present(): void
    {
        self::assertInstanceOf(
            ServerPagingHandler::class,
            $this->subject->get(
                Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'),
                new ControlBag(new PagingControl(10)),
            ),
        );
    }

    public function test_it_should_get_a_root_dse_handler(): void
    {
        self::assertInstanceOf(
            ServerRootDseHandler::class,
            $this->subject->get(
                Operations::read(''),
                new ControlBag(),
            ),
        );
    }

    public function test_it_should_get_a_subschema_handler(): void
    {
        self::assertInstanceOf(
            ServerSubschemaHandler::class,
            $this->subject->get(
                Operations::read('cn=Subschema'),
                new ControlBag(),
            ),
        );
    }

    public function test_it_should_get_the_unsupported_extended_handler_for_an_unknown_oid(): void
    {
        self::assertInstanceOf(
            ServerUnsupportedExtendedHandler::class,
            $this->subject->get(
                Operations::extended('1.2.3.4.5.6.7.8.9'),
                new ControlBag(),
            ),
        );
    }

    public function test_it_should_get_an_unbind_handler(): void
    {
        self::assertInstanceOf(
            ServerUnbindHandler::class,
            $this->subject->get(
                Operations::unbind(),
                new ControlBag(),
            ),
        );
    }

    public function test_it_should_get_the_dispatch_handler_for_common_requests(): void
    {
        self::assertInstanceOf(
            ServerDispatchHandler::class,
            $this->subject->get(Operations::delete('cn=foo'), new ControlBag()),
        );
        self::assertInstanceOf(
            ServerDispatchHandler::class,
            $this->subject->get(Operations::add(Entry::fromArray('cn=foo')), new ControlBag()),
        );
        self::assertInstanceOf(
            ServerDispatchHandler::class,
            $this->subject->get(Operations::compare('cn=foo', 'foo', 'bar'), new ControlBag()),
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

    /**
     * @return array<array{HandlerId}>
     */
    public static function handlerIdProvider(): array
    {
        return array_map(
            static fn(HandlerId $handlerId): array => [$handlerId],
            HandlerId::cases(),
        );
    }

    #[DataProvider('handlerIdProvider')]
    public function test_every_route_has_a_registered_factory(HandlerId $handlerId): void
    {
        $container = Container::forServer(new ServerOptions());

        self::assertInstanceOf(
            ServerProtocolHandlerInterface::class,
            $container->get(ProtocolHandlerFactoryMap::class)->make(
                $handlerId,
                $this->handlerContext(),
            ),
        );
    }

    private function handlerContext(?PasswordPolicyContext $passwordPolicyContext = null): HandlerContext
    {
        return new HandlerContext(
            connection: $this->createMock(ConnectionControl::class),
            eventLogger: new EventLogger(null),
            requestHistory: new RequestHistory(),
            passwordPolicyContext: $passwordPolicyContext,
        );
    }
}
