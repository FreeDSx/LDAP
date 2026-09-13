<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Proxy\ProxyUpstreamSession;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ProxyUpstreamSessionTest extends TestCase
{
    private LdapClient&MockObject $client;

    private ProxyUpstreamSession $subject;

    protected function setUp(): void
    {
        $this->client = $this->createMock(LdapClient::class);
        $this->subject = new ProxyUpstreamSession($this->client);
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

        $this->makeStartTlsSession()->bind(
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

        $this->makeStartTlsSession()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
    }

    public function test_it_upgrades_the_link_before_anything_that_is_not_a_bind(): void
    {
        $this->client
            ->expects(self::once())
            ->method('startTls');

        $this->makeStartTlsSession()->ensureReady();
    }

    public function test_it_leaves_the_link_alone_when_start_tls_is_not_configured(): void
    {
        $this->client
            ->expects(self::never())
            ->method('startTls');

        $this->subject->ensureReady();
    }

    public function test_it_does_not_upgrade_a_link_already_encrypted(): void
    {
        $this->client
            ->method('isEncrypted')
            ->willReturn(true);
        $this->client
            ->expects(self::never())
            ->method('startTls');

        $this->makeStartTlsSession()->ensureReady();
    }

    public function test_it_replaces_a_connection_the_upstream_closed_before_sending_anything(): void
    {
        $this->client
            ->method('isConnected')
            ->willReturn(false);
        $this->client
            ->expects(self::once())
            ->method('disconnect');

        $this->subject->ensureReady();
    }

    public function test_it_does_not_replace_a_closed_connection_that_carried_a_bound_identity(): void
    {
        $calls = 0;
        $this->client
            ->method('isConnected')
            ->willReturnCallback(function () use (&$calls): bool {
                $calls++;

                return $calls === 1;
            });
        $this->subject->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        $this->client
            ->expects(self::never())
            ->method('disconnect');

        $this->expectException(ConnectionException::class);

        $this->subject->ensureReady();
    }

    public function test_it_keeps_a_live_connection_before_sending_anything(): void
    {
        $this->client
            ->method('isConnected')
            ->willReturn(true);
        $this->client
            ->expects(self::never())
            ->method('disconnect');

        $this->subject->ensureReady();
    }

    public function test_it_sends_a_bind_that_fails_on_the_transport_only_once(): void
    {
        $this->client
            ->expects(self::once())
            ->method('bind')
            ->willThrowException(new ConnectionException('The connection to the server has been lost.'));

        $this->expectException(ConnectionException::class);

        try {
            $this->subject->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
        } finally {
            self::assertFalse($this->subject->isBound());
        }
    }

    public function test_it_drops_the_connection_after_a_bind_fails_on_the_transport(): void
    {
        $this->client
            ->method('isConnected')
            ->willReturn(true);
        $this->client
            ->method('bind')
            ->willThrowException(new ConnectionException('The connection was idle for longer than the read timeout.'));
        $this->client
            ->expects(self::once())
            ->method('disconnect');

        $this->expectException(ConnectionException::class);

        $this->subject->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
    }

    public function test_it_does_not_reissue_a_bind_the_upstream_refused(): void
    {
        $this->client
            ->expects(self::once())
            ->method('bind')
            ->willThrowException(new BindException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
            ));

        $this->expectException(BindException::class);

        $this->subject->bind(
            'cn=user,dc=foo,dc=bar',
            'wrong',
        );
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

    private function makeStartTlsSession(): ProxyUpstreamSession
    {
        return new ProxyUpstreamSession(
            client: $this->client,
            useStartTls: true,
        );
    }
}
