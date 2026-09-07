<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Proxy\ProxyAuthenticator;
use FreeDSx\Ldap\Server\Proxy\ProxyUpstreamSession;
use FreeDSx\Ldap\Server\Utility\ExponentialBackoff;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Clock\RecordingSleeper;

final class ProxyAuthenticatorTest extends TestCase
{
    private LdapClient&MockObject $client;

    private ProxyAuthenticator $subject;

    protected function setUp(): void
    {
        $this->client = $this->createMock(LdapClient::class);
        $this->subject = new ProxyAuthenticator(new ProxyUpstreamSession(
            client: $this->client,
            sleeper: new RecordingSleeper(),
            maxAttempts: 1,
            backoff: new ExponentialBackoff(
                base: 0.01,
                max: 0.02,
            ),
        ));
    }

    public function test_it_binds_upstream_and_returns_a_token(): void
    {
        $this->client
            ->expects(self::once())
            ->method('bind')
            ->with('cn=user,dc=foo,dc=bar', '12345');

        $token = $this->subject->authenticate(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        self::assertSame('cn=user,dc=foo,dc=bar', $token->getUsername());
    }

    public function test_it_answers_rather_than_raises_when_the_upstream_is_gone(): void
    {
        $this->client
            ->method('bind')
            ->willThrowException(new ConnectionException('gone'));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNAVAILABLE);

        $this->subject->authenticate(
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

        $this->subject->authenticate(
            'cn=user,dc=foo,dc=bar',
            'wrong',
        );
    }

    public function test_it_does_not_hold_a_session_after_a_failed_bind(): void
    {
        $session = new ProxyUpstreamSession(
            client: $this->client,
            sleeper: new RecordingSleeper(),
            maxAttempts: 1,
        );
        $this->client
            ->method('bind')
            ->willThrowException(new BindException('Invalid credentials.', ResultCode::INVALID_CREDENTIALS));

        try {
            (new ProxyAuthenticator($session))->authenticate(
                'cn=user,dc=foo,dc=bar',
                'wrong',
            );
        } catch (OperationException) {
        }

        self::assertFalse($session->isBound());
    }
}
