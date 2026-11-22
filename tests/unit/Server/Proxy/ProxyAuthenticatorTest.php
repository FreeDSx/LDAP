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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ProxyAuthenticatorTest extends TestCase
{
    private LdapClient&MockObject $client;

    private ProxyAuthenticator $subject;

    private ProxyAuthenticator $asking;

    protected function setUp(): void
    {
        $this->client = $this->createMock(LdapClient::class);
        $this->subject = new ProxyAuthenticator(new ProxyUpstreamSession($this->client));
        $this->asking = new ProxyAuthenticator(
            session: new ProxyUpstreamSession($this->client),
            asksUpstreamIdentity: true,
        );
    }

    public function test_it_does_not_ask_the_upstream_who_it_bound_as_by_default(): void
    {
        $this->client
            ->expects(self::never())
            ->method('whoami');

        $token = $this->subject->authenticate(
            'commonName=user,domainComponent=foo,dc=bar',
            '12345',
        );

        self::assertSame(
            'dn:commonName=user,domainComponent=foo,dc=bar',
            $token->getAuthzId()->toString(),
        );
    }

    public function test_it_takes_the_identity_the_upstream_reports_and_keeps_the_name_as_bound(): void
    {
        $this->client
            ->method('whoami')
            ->willReturn('dn:cn=user,dc=foo,dc=bar');

        $token = $this->asking->authenticate(
            'commonName=user,domainComponent=foo,dc=bar',
            '12345',
        );

        self::assertSame(
            [
                'dn:cn=user,dc=foo,dc=bar',
                'commonName=user,domainComponent=foo,dc=bar',
            ],
            [
                $token->getAuthzId()->toString(),
                $token->getUsername(),
            ],
        );
    }

    public function test_it_takes_a_username_the_upstream_reports(): void
    {
        $this->client
            ->method('whoami')
            ->willReturn('u:FOO\user');

        $token = $this->asking->authenticate(
            'user@foo.bar',
            '12345',
        );

        self::assertSame(
            'u:FOO\user',
            $token->getAuthzId()->toString(),
        );
    }

    #[DataProvider('unnamedIdentityProvider')]
    public function test_it_keeps_the_name_as_bound_when_the_upstream_names_no_identity(?string $answer): void
    {
        $this->client
            ->method('whoami')
            ->willReturn($answer);

        $token = $this->asking->authenticate(
            'commonName=user,domainComponent=foo,dc=bar',
            '12345',
        );

        self::assertSame(
            'dn:commonName=user,domainComponent=foo,dc=bar',
            $token->getAuthzId()->toString(),
        );
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function unnamedIdentityProvider(): iterable
    {
        yield 'no answer' => [null];
        yield 'the anonymous identity' => [''];
        yield 'an empty dn' => ['dn:'];
        yield 'an empty username' => ['u:'];
        yield 'an answer in neither form' => ['cn=user,dc=foo,dc=bar'];
        yield 'a dn that does not parse' => ['dn:not a dn'];
    }

    public function test_it_answers_unavailable_when_asking_who_it_bound_as_fails_on_the_transport(): void
    {
        $this->client
            ->method('whoami')
            ->willThrowException(new ConnectionException('gone'));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNAVAILABLE);

        $this->asking->authenticate(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
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
        $session = new ProxyUpstreamSession($this->client);
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
