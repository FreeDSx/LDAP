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
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ServerProtocolHandlerFactoryTest extends TestCase
{
    private ServerProtocolHandlerFactory $subject;

    protected function setUp(): void
    {
        $this->subject = new ServerProtocolHandlerFactory(TestServerOptions::defaults());
    }

    #[DataProvider('routes')]
    public function test_it_resolves_the_route_for_a_request(
        RequestInterface $request,
        ControlBag $controls,
        HandlerId $expected,
    ): void {
        self::assertSame(
            $expected,
            $this->subject->routeIdFor(
                $request,
                $controls,
            ),
        );
    }

    public function test_a_base_scope_monitor_search_routes_to_monitor_when_enabled(): void
    {
        $factory = new ServerProtocolHandlerFactory(
            (TestServerOptions::defaults())->setMonitorEnabled(true),
        );

        self::assertSame(
            HandlerId::Monitor,
            $factory->routeIdFor(
                Operations::read('cn=monitor'),
                new ControlBag(),
            ),
        );
    }

    /**
     * @return iterable<string, array{RequestInterface, ControlBag, HandlerId}>
     */
    public static function routes(): iterable
    {
        yield 'abandon' => [new AbandonRequest(1), new ControlBag(), HandlerId::Abandon];
        yield 'cancel' => [new CancelRequest(1), new ControlBag(), HandlerId::Cancel];
        yield 'whoami' => [Operations::whoami(), new ControlBag(), HandlerId::WhoAmI];
        yield 'password modify' => [Operations::extended(ExtendedRequest::OID_PWD_MODIFY), new ControlBag(), HandlerId::PasswordModify];
        yield 'start tls' => [Operations::extended(ExtendedRequest::OID_START_TLS), new ControlBag(), HandlerId::StartTls];
        yield 'unsupported extended' => [Operations::extended('1.2.3.4.5.6.7.8.9'), new ControlBag(), HandlerId::UnsupportedExtended];
        yield 'root dse' => [Operations::read(''), new ControlBag(), HandlerId::RootDse];
        yield 'subschema' => [Operations::read('cn=Subschema'), new ControlBag(), HandlerId::Subschema];
        yield 'monitor disabled routes to search' => [Operations::read('cn=monitor'), new ControlBag(), HandlerId::Search];
        yield 'paging' => [Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'), new ControlBag(new PagingControl(10)), HandlerId::Paging];
        yield 'search' => [Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'), new ControlBag(), HandlerId::Search];
        yield 'unbind' => [Operations::unbind(), new ControlBag(), HandlerId::Unbind];
        yield 'delete dispatch' => [Operations::delete('cn=foo'), new ControlBag(), HandlerId::Dispatch];
    }
}
