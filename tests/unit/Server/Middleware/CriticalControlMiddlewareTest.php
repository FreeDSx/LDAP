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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;
use FreeDSx\Ldap\Protocol\Factory\HandlerRouteResolverInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Middleware\CriticalControlMiddleware;
use FreeDSx\Ldap\Server\Middleware\CriticalControlValidator;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Middleware\ServerControlRegistry;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;

final class CriticalControlMiddlewareTest extends TestCase
{
    private HandlerRouteResolverInterface&MockObject $resolver;

    private CriticalControlMiddleware $subject;

    private RecordingMiddlewareHandler $next;

    protected function setUp(): void
    {
        $this->resolver = $this->createMock(HandlerRouteResolverInterface::class);
        $this->subject = new CriticalControlMiddleware(
            $this->resolver,
            new CriticalControlValidator(new ServerControlRegistry()),
        );
        $this->next = new RecordingMiddlewareHandler(new CallLog());
    }

    public function test_a_critical_unsupported_control_is_rejected(): void
    {
        $this->routeResolvesTo(HandlerId::Search);

        try {
            $this->subject->process(
                $this->contextWith(new Control('1.2.3.4.5', criticality: true)),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                $e->getCode(),
            );
            self::assertSame(
                'Critical control 1.2.3.4.5 is not supported.',
                $e->getMessage(),
            );
        }

        self::assertNull(
            $this->next->received,
            'The next handler must not be reached when a critical control is rejected.',
        );
    }

    public function test_a_non_critical_unsupported_control_passes_through(): void
    {
        $this->routeResolvesTo(HandlerId::Search);

        $this->subject->process(
            $this->contextWith(new Control('1.2.3.4.5', criticality: false)),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_a_supported_critical_control_passes_through(): void
    {
        $this->routeResolvesTo(HandlerId::Search);

        $this->subject->process(
            $this->contextWith(new Control(Control::OID_SORTING, criticality: true)),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_a_critical_proxy_authorization_control_passes_on_any_checked_route(): void
    {
        $this->routeResolvesTo(HandlerId::RootDse);

        $this->subject->process(
            $this->contextWith(new Control(Control::OID_PROXY_AUTHORIZATION, criticality: true)),
            $this->next,
        );

        self::assertNotNull(
            $this->next->received,
            'Proxied authorization is gated upstream, so the check must accept it everywhere.',
        );
    }

    public function test_exempt_handlers_skip_the_check_entirely(): void
    {
        $this->routeResolvesTo(HandlerId::Unbind);

        $this->subject->process(
            $this->contextWith(new Control('1.2.3.4.5', criticality: true)),
            $this->next,
        );

        self::assertNotNull(
            $this->next->received,
            'Unbind carries no response, so the critical-control check does not apply.',
        );
    }

    private function routeResolvesTo(HandlerId $id): void
    {
        $this->resolver
            ->method('routeIdFor')
            ->willReturn($id);
    }

    private function contextWith(Control ...$controls): ServerRequestContext
    {
        return new ServerRequestContext(
            new LdapMessageRequest(
                1,
                new DeleteRequest('cn=foo,dc=bar'),
                ...$controls,
            ),
            $this->createMock(TokenInterface::class),
        );
    }
}
