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

namespace Tests\Unit\FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Proxy\ProxyBindResetMiddleware;
use FreeDSx\Ldap\Server\Proxy\ProxyUpstreamSession;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallbackMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\StubMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class ProxyBindResetMiddlewareTest extends TestCase
{
    private LdapClient&MockObject $client;

    private ServerAuthorization $authorization;

    private ProxyUpstreamSession $session;

    private ProxyBindResetMiddleware $subject;

    protected function setUp(): void
    {
        $this->client = $this->createMock(LdapClient::class);
        $this->client
            ->method('isConnected')
            ->willReturn(true);
        $this->authorization = new ServerAuthorization(TestServerOptions::defaults());
        $this->session = new ProxyUpstreamSession($this->client);
        $this->subject = new ProxyBindResetMiddleware(
            $this->authorization,
            $this->session,
        );

        $this->session->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
    }

    public function test_a_request_after_the_session_lost_its_bind_ends_the_upstream_session(): void
    {
        $this->client
            ->expects(self::once())
            ->method('unbind');

        $this->subject->process(
            $this->contextFor(self::search()),
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
        );

        self::assertFalse($this->session->isBound());
    }

    public function test_a_request_on_a_session_holding_its_bind_keeps_the_upstream_session(): void
    {
        $this->authorization->setToken(BindToken::fromDn('cn=user,dc=foo,dc=bar'));
        $this->client
            ->expects(self::never())
            ->method('unbind');

        $this->subject->process(
            $this->contextFor(self::search()),
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
        );

        self::assertTrue($this->session->isBound());
    }

    public function test_a_failed_bind_ends_the_upstream_session_when_authentication_is_not_required(): void
    {
        $authorization = new ServerAuthorization(TestServerOptions::defaults()->setRequireAuthentication(false));
        $authorization->setToken(BindToken::fromDn('cn=user,dc=foo,dc=bar'));
        $subject = new ProxyBindResetMiddleware(
            $authorization,
            $this->session,
        );
        $this->client
            ->expects(self::once())
            ->method('unbind');

        $this->expectException(OperationException::class);

        $subject->process(
            $this->contextFor(new SimpleBindRequest(
                'cn=other,dc=foo,dc=bar',
                'wrong',
            )),
            new CallbackMiddlewareHandler(function () use ($authorization): never {
                $authorization->setToken(new AnonToken());

                throw new OperationException(
                    'Invalid credentials.',
                    ResultCode::INVALID_CREDENTIALS,
                );
            }),
        );
    }

    public function test_an_anonymous_rebind_ends_the_upstream_session_when_authentication_is_not_required(): void
    {
        $authorization = new ServerAuthorization(TestServerOptions::defaults()->setRequireAuthentication(false));
        $authorization->setToken(BindToken::fromDn('cn=user,dc=foo,dc=bar'));
        $subject = new ProxyBindResetMiddleware(
            $authorization,
            $this->session,
        );
        $this->client
            ->expects(self::once())
            ->method('unbind');

        $subject->process(
            $this->contextFor(new AnonBindRequest()),
            new CallbackMiddlewareHandler(function () use ($authorization): OperationOutcomeResult {
                $authorization->setToken(new AnonToken());

                return OperationOutcomeResult::succeeded();
            }),
        );

        self::assertFalse($this->session->isBound());
    }

    private function contextFor(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(new LdapMessageRequest(
            2,
            $request,
        ));
    }

    private static function search(): SearchRequest
    {
        return (new SearchRequest(Filters::present('objectClass')))->base('dc=foo,dc=bar');
    }
}
