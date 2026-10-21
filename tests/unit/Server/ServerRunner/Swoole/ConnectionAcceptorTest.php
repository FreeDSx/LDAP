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

use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\ConnectionAcceptor;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared\ConnectionSlots;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Swoole\Coroutine;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\ScriptedSocketServer;

final class ConnectionAcceptorTest extends TestCase
{
    use RequiresExtensionsTrait;

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
