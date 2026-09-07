<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Proxy\ProxyAuthenticator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ProxyAuthenticatorTest extends TestCase
{
    private LdapClient&MockObject $client;

    protected function setUp(): void
    {
        $this->client = $this->createMock(LdapClient::class);
    }

    public function test_it_binds_upstream_and_returns_a_token(): void
    {
        $this->client
            ->expects(self::once())
            ->method('bind')
            ->with('cn=user,dc=foo,dc=bar', '12345');
        $this->client
            ->expects(self::never())
            ->method('startTls');

        $token = (new ProxyAuthenticator($this->client))->authenticate(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        self::assertSame('cn=user,dc=foo,dc=bar', $token->getUsername());
    }

    public function test_it_issues_start_tls_before_binding_when_configured(): void
    {
        $this->client
            ->expects(self::once())
            ->method('startTls');
        $this->client
            ->expects(self::once())
            ->method('bind');

        (new ProxyAuthenticator($this->client, true))->authenticate(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
    }

    public function test_it_does_not_re_issue_start_tls_on_a_connection_already_upgraded(): void
    {
        $this->client
            ->method('isEncrypted')
            ->willReturn(true);
        $this->client
            ->expects(self::never())
            ->method('startTls');
        $this->client
            ->expects(self::once())
            ->method('bind');

        (new ProxyAuthenticator($this->client, true))->authenticate(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
    }

    public function test_it_answers_rather_than_raises_when_the_upstream_is_gone(): void
    {
        $this->client
            ->method('bind')
            ->willThrowException(new ConnectionException('gone'));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNAVAILABLE);

        (new ProxyAuthenticator($this->client))->authenticate(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
    }

    public function test_it_answers_rather_than_raises_when_start_tls_cannot_be_issued(): void
    {
        $this->client
            ->method('startTls')
            ->willThrowException(new ConnectionException('gone'));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNAVAILABLE);

        (new ProxyAuthenticator($this->client, true))->authenticate(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
    }

    public function test_it_translates_an_upstream_bind_failure(): void
    {
        $this->client
            ->method('bind')
            ->willThrowException(new BindException('Invalid credentials.', ResultCode::INVALID_CREDENTIALS));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        (new ProxyAuthenticator($this->client))->authenticate(
            'cn=user,dc=foo,dc=bar',
            'wrong',
        );
    }
}
