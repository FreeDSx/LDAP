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

namespace Tests\Unit\FreeDSx\Ldap\Server\Logging;

use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketAddress;
use PHPUnit\Framework\TestCase;

final class ConnectionContextTest extends TestCase
{
    public function test_empty_context_produces_an_empty_log_context(): void
    {
        self::assertSame(
            [],
            (new ConnectionContext())->toLogContext(),
        );
    }

    public function test_only_provided_fields_appear_in_the_log_context(): void
    {
        self::assertSame(
            ['pid' => 4242],
            (new ConnectionContext(pid: 4242))->toLogContext(),
        );

        self::assertSame(
            ['conn_id' => 7],
            (new ConnectionContext(connId: 7))->toLogContext(),
        );

        self::assertSame(
            ['remote_ip' => '10.0.0.1'],
            (new ConnectionContext(remoteIp: '10.0.0.1'))->toLogContext(),
        );
    }

    public function test_all_fields_combine_in_the_log_context(): void
    {
        self::assertSame(
            [
                'pid' => 4242,
                'conn_id' => 7,
                'remote_ip' => '10.0.0.1',
            ],
            (new ConnectionContext(
                pid: 4242,
                connId: 7,
                remoteIp: '10.0.0.1',
            ))->toLogContext(),
        );
    }

    public function test_a_socket_gives_the_context_its_client_address(): void
    {
        self::assertSame(
            [
                'pid' => 4242,
                'remote_ip' => '10.0.0.1',
            ],
            ConnectionContext::forSocket(
                $this->socketFrom(SocketAddress::tryFromName('[::ffff:10.0.0.1]:40000')),
                pid: 4242,
            )->toLogContext(),
        );
    }

    public function test_a_unix_socket_gives_the_context_no_client_address(): void
    {
        self::assertSame(
            ['conn_id' => 7],
            ConnectionContext::forSocket(
                $this->socketFrom(SocketAddress::unix()),
                connId: 7,
            )->toLogContext(),
        );
    }

    public function test_a_socket_without_a_known_peer_gives_the_context_no_client_address(): void
    {
        self::assertSame(
            [],
            ConnectionContext::forSocket($this->socketFrom(null))->toLogContext(),
        );
    }

    private function socketFrom(?SocketAddress $address): Socket
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('getPeerAddress')->willReturn($address);

        return $socket;
    }
}
