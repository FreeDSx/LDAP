<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\NoticeOfDisconnectException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Server\Proxy\ProxyUpstreamSession;
use FreeDSx\Ldap\Server\Utility\ExponentialBackoff;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Clock\RecordingSleeper;

final class ProxyUpstreamSessionTest extends TestCase
{
    private LdapClient&MockObject $client;

    private RecordingSleeper $sleeper;

    private ProxyUpstreamSession $subject;

    protected function setUp(): void
    {
        $this->client = $this->createMock(LdapClient::class);
        $this->sleeper = new RecordingSleeper();
        $this->subject = $this->makeSession();
    }

    public function test_it_is_not_bound_before_a_bind(): void
    {
        self::assertFalse($this->subject->isBound());
    }

    public function test_it_is_bound_after_binding_upstream(): void
    {
        $this->client
            ->expects(self::once())
            ->method('bind')
            ->with('cn=user,dc=foo,dc=bar', '12345');

        $this->subject->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        self::assertTrue($this->subject->isBound());
    }

    public function test_it_issues_start_tls_before_binding_when_configured(): void
    {
        $this->client
            ->expects(self::once())
            ->method('startTls');
        $this->client
            ->expects(self::once())
            ->method('bind');

        $this->makeSession(useStartTls: true)->bind(
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

        $this->makeSession(useStartTls: true)->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
    }

    public function test_it_reissues_a_bind_that_failed_on_the_transport(): void
    {
        $attempts = 0;
        $this->client
            ->method('bind')
            ->willReturnCallback(function () use (&$attempts): LdapMessageResponse {
                $attempts++;

                if ($attempts < 3) {
                    throw new ConnectionException('gone');
                }

                return new LdapMessageResponse(
                    1,
                    new BindResponse(new LdapResult(ResultCode::SUCCESS)),
                );
            });

        $this->subject->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        self::assertSame(
            3,
            $attempts,
        );
        self::assertCount(
            2,
            $this->sleeper->durations,
        );
        self::assertTrue($this->subject->isBound());
    }

    public function test_it_gives_up_once_the_attempts_are_spent(): void
    {
        $this->client
            ->method('bind')
            ->willThrowException(new ConnectionException('gone'));

        $this->expectException(ConnectionException::class);

        try {
            $this->subject->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
        } finally {
            self::assertCount(
                2,
                $this->sleeper->durations,
            );
            self::assertFalse($this->subject->isBound());
        }
    }

    public function test_it_does_not_reissue_a_bind_the_upstream_answered_by_disconnecting(): void
    {
        $attempts = 0;
        $this->client
            ->method('bind')
            ->willReturnCallback(function () use (&$attempts): never {
                $attempts++;

                throw new NoticeOfDisconnectException('the peer said so');
            });

        $this->expectException(NoticeOfDisconnectException::class);

        try {
            $this->subject->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
        } finally {
            self::assertSame(
                1,
                $attempts,
            );
            self::assertSame(
                [],
                $this->sleeper->durations,
            );
        }
    }

    public function test_it_does_not_reissue_a_bind_the_upstream_refused(): void
    {
        $attempts = 0;
        $this->client
            ->method('bind')
            ->willReturnCallback(function () use (&$attempts): never {
                $attempts++;

                throw new BindException('Invalid credentials.', ResultCode::INVALID_CREDENTIALS);
            });

        $this->expectException(BindException::class);

        try {
            $this->subject->bind(
                'cn=user,dc=foo,dc=bar',
                'wrong',
            );
        } finally {
            self::assertSame(
                1,
                $attempts,
            );
        }
    }

    public function test_it_unbinds_upstream_when_reset_while_bound(): void
    {
        $this->client
            ->method('isConnected')
            ->willReturn(true);
        $this->client
            ->expects(self::once())
            ->method('unbind');

        $this->subject->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
        $this->subject->reset();

        self::assertFalse($this->subject->isBound());
    }

    public function test_it_leaves_an_unbound_session_alone_when_reset(): void
    {
        $this->client
            ->expects(self::never())
            ->method('unbind');

        $this->subject->reset();

        self::assertFalse($this->subject->isBound());
    }

    public function test_it_closes_the_connection_when_the_upstream_unbind_cannot_be_sent(): void
    {
        $this->client
            ->method('isConnected')
            ->willReturn(true);
        $this->client
            ->method('unbind')
            ->willThrowException(new ConnectionException('gone'));
        $this->client
            ->expects(self::once())
            ->method('disconnect');

        $this->subject->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
        $this->subject->reset();

        self::assertFalse($this->subject->isBound());
    }

    private function makeSession(bool $useStartTls = false): ProxyUpstreamSession
    {
        return new ProxyUpstreamSession(
            client: $this->client,
            useStartTls: $useStartTls,
            sleeper: $this->sleeper,
            maxAttempts: 3,
            backoff: new ExponentialBackoff(
                base: 0.01,
                max: 0.02,
            ),
        );
    }
}
