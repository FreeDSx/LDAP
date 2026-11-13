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

namespace Tests\Unit\FreeDSx\Ldap\Server\ServerRunner\Swoole;

use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\ConnectionAcceptor;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared\ConnectionSlots;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Exception\AcceptException;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketAddress;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Swoole\Coroutine;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\ScriptedSocketServer;

final class ConnectionAcceptorTest extends TestCase
{
    use RequiresExtensionsTrait;

    /**
     * The longest a connection waits on its shutdown notice before it ends on its own.
     */
    private const CONNECTION_HOLD_SECONDS = 5.0;

    private RecordingLogger $logger;

    private ServerProtocolFactoryInterface&MockObject $protocolFactory;

    private ServerOptions $options;

    private ConnectionSlots $connectionSlots;

    private ConnectionAcceptor $subject;

    /**
     * @var list<resource>
     */
    private array $peers = [];

    protected function setUp(): void
    {
        $this->requireSwoole();

        $this->logger = new RecordingLogger();
        $this->protocolFactory = $this->createMock(ServerProtocolFactoryInterface::class);
        $this->options = TestServerOptions::defaults();
        $this->connectionSlots = new ConnectionSlots();
        $this->subject = new ConnectionAcceptor(
            $this->protocolFactory,
            $this->options,
            new EventLogger(
                $this->logger,
                EventLogPolicy::default(),
            ),
            false,
            $this->connectionSlots,
        );
    }

    protected function tearDown(): void
    {
        foreach ($this->peers as $peer) {
            fclose($peer);
        }
    }

    public function test_a_connection_accepted_as_shutdown_begins_is_rejected_and_closed(): void
    {
        $arriving = $this->connectedSocket();
        $server = new ScriptedSocketServer(
            [$arriving],
            onArrival: $this->subject->shutdown(...),
        );

        $this->protocolFactory
            ->expects(self::never())
            ->method('make');

        Coroutine\run(function () use ($server): void {
            $this->subject->accept($server);
        });

        self::assertSame(
            ['shutting_down'],
            $this->rejectionReasons(),
        );
        self::assertFalse($arriving->isConnected());
    }

    public function test_a_connection_over_the_limit_is_rejected_closed_and_no_longer_tracked(): void
    {
        $this->options->getNetworkConfig()->setMaxConnections(1);
        $this->connectionSlots->tryAcquire(1);
        $arriving = $this->connectedSocket();
        $server = new ScriptedSocketServer(
            [$arriving],
            onDrained: $this->subject->shutdown(...),
        );

        $this->protocolFactory
            ->expects(self::never())
            ->method('make');

        Coroutine\run(function () use ($server): void {
            $this->subject->accept($server);
        });

        self::assertSame(
            ['connection_limit'],
            $this->rejectionReasons(),
        );
        self::assertSame(
            [],
            $server->getClients(),
        );
        self::assertFalse($arriving->isConnected());
    }

    public function test_a_client_is_served_and_logged_with_its_address(): void
    {
        $handler = $this->createMock(ServerProtocolHandler::class);
        $server = new ScriptedSocketServer(
            [$this->socketAt('192.0.2.7:50000')],
            onDrained: $this->subject->shutdown(...),
        );

        $this->protocolFactory
            ->expects(self::once())
            ->method('make')
            ->with(
                self::anything(),
                self::callback(static fn(ConnectionContext $context): bool => $context->remoteIp === '192.0.2.7'),
            )
            ->willReturn($handler);

        Coroutine\run(function () use ($server): void {
            $this->subject->accept($server);
        });

        self::assertSame(
            '192.0.2.7',
            $this->contextOf(ServerEvent::ClientConnected)[EventContext::REMOTE_IP] ?? null,
        );
    }

    public function test_a_rejected_client_is_logged_with_its_address(): void
    {
        $this->options->getNetworkConfig()->setMaxConnections(1);
        $this->connectionSlots->tryAcquire(1);
        $server = new ScriptedSocketServer(
            [$this->socketAt('192.0.2.7:50000')],
            onDrained: $this->subject->shutdown(...),
        );

        Coroutine\run(function () use ($server): void {
            $this->subject->accept($server);
        });

        self::assertSame(
            '192.0.2.7',
            $this->contextOf(ServerEvent::ClientRejected)[EventContext::REMOTE_IP] ?? null,
        );
    }

    public function test_failed_accepts_are_logged_once_and_the_client_after_them_is_served(): void
    {
        $failure = new AcceptException('Unable to accept a waiting client: Too many open files');
        $server = new ScriptedSocketServer(
            [$failure, $failure, $this->connectedSocket()],
            onDrained: $this->subject->shutdown(...),
        );

        $this->protocolFactory
            ->expects(self::once())
            ->method('make')
            ->willThrowException(new RuntimeException('The client reached the protocol handler.'));

        Coroutine\run(function () use ($server): void {
            $this->subject->accept($server);
        });

        self::assertSame(
            [
                ServerEvent::ServerAcceptFailed->value,
                ServerEvent::ServerAcceptRecovered->value,
            ],
            $this->acceptEvents(),
        );
    }

    public function test_an_unexpected_accept_error_stops_accepting(): void
    {
        $server = new ScriptedSocketServer(
            [],
            onDrained: static fn() => throw new RuntimeException('The listener broke.'),
        );

        Coroutine\run(function () use ($server): void {
            $this->subject->accept($server);
        });

        self::assertSame(
            [ServerEvent::ServerAcceptFailed->value],
            $this->acceptEvents(),
        );
    }

    public function test_a_client_slow_to_take_its_shutdown_notice_holds_up_no_other_notice(): void
    {
        $notified = new CallLog();
        $this->protocolFactory
            ->method('make')
            ->willReturnOnConsecutiveCalls(
                $this->connectionHeldUntilShutdown(
                    'stalled',
                    0.2,
                    $notified,
                ),
                $this->connectionHeldUntilShutdown(
                    'reading',
                    0.001,
                    $notified,
                ),
            );
        $server = new ScriptedSocketServer(
            [$this->connectedSocket(), $this->connectedSocket()],
            onDrained: $this->subject->shutdown(...),
        );

        Coroutine\run(function () use ($server): void {
            $this->subject->accept($server);
        });

        self::assertSame(
            ['reading', 'stalled'],
            $notified->entries,
        );
    }

    public function test_the_drain_timer_runs_while_a_shutdown_notice_is_still_going_out(): void
    {
        $this->options->getNetworkConfig()->setShutdownTimeout(1);
        $this->protocolFactory
            ->method('make')
            ->willReturn($this->connectionHeldUntilShutdown(
                'stalled',
                1.5,
                new CallLog(),
            ));
        $server = new ScriptedSocketServer(
            [$this->connectedSocket()],
            onDrained: $this->subject->shutdown(...),
        );

        Coroutine\run(function () use ($server): void {
            $this->subject->accept($server);
        });

        self::assertContains(
            ServerEvent::ShutdownForced->value,
            $this->logger->events(),
        );
    }

    /**
     * A connection held open until its shutdown notice goes out after the given seconds.
     */
    private function connectionHeldUntilShutdown(
        string $name,
        float $noticeSeconds,
        CallLog $notified,
    ): ServerProtocolHandler {
        $handler = $this->createMock(ServerProtocolHandler::class);
        $handler
            ->method('handle')
            ->willReturnCallback(static function () use ($name, $notified): ?ConnectionObservation {
                $deadline = microtime(true) + self::CONNECTION_HOLD_SECONDS;
                while (!in_array($name, $notified->entries, true) && microtime(true) < $deadline) {
                    Coroutine::sleep(0.01);
                }

                return null;
            });
        $handler
            ->method('shutdown')
            ->willReturnCallback(static function () use ($name, $noticeSeconds, $notified): void {
                Coroutine::sleep($noticeSeconds);
                $notified->record($name);
            });

        return $handler;
    }

    private function connectedSocket(): Socket
    {
        $pair = stream_socket_pair(
            STREAM_PF_UNIX,
            STREAM_SOCK_STREAM,
            STREAM_IPPROTO_IP,
        );
        self::assertIsArray($pair);
        $this->peers[] = $pair[1];

        return new Socket($pair[0]);
    }

    /**
     * A client socket whose peer is at the given address.
     */
    private function socketAt(string $address): Socket
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('getPeerAddress')->willReturn(SocketAddress::tryFromName($address));

        return $socket;
    }

    /**
     * @return array<string, mixed>
     */
    private function contextOf(ServerEvent $event): array
    {
        foreach ($this->logger->records as $record) {
            if (($record['context'][EventContext::EVENT] ?? null) === $event->value) {
                return $record['context'];
            }
        }

        self::fail(sprintf(
            'No %s event was logged.',
            $event->value,
        ));
    }

    /**
     * @return list<mixed>
     */
    private function acceptEvents(): array
    {
        $accepts = [
            ServerEvent::ServerAcceptFailed->value,
            ServerEvent::ServerAcceptRecovered->value,
        ];

        return array_values(array_filter(
            $this->logger->events(),
            static fn(mixed $event): bool => in_array(
                $event,
                $accepts,
                true,
            ),
        ));
    }

    /**
     * @return list<mixed>
     */
    private function rejectionReasons(): array
    {
        $reasons = [];

        foreach ($this->logger->records as $record) {
            if (($record['context'][EventContext::EVENT] ?? null) !== ServerEvent::ClientRejected->value) {
                continue;
            }
            $reasons[] = $record['context'][EventContext::REASON] ?? null;
        }

        return $reasons;
    }
}
