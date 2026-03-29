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

namespace FreeDSx\Ldap\Server\ServerRunner;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketServer;
use Psr\Log\LoggerInterface;
use Swoole\Coroutine;
use Swoole\Process;
use Swoole\Runtime;
use Throwable;

/**
 * A server runner that uses Swoole coroutines instead of forked processes.
 *
 * Each incoming client connection is handled in its own coroutine within a
 * single PHP process. This means all coroutines share the same memory, making
 * in-memory storage adapters safe to use with concurrent clients.
 *
 * Note on JsonFileStorageAdapter: although Swoole hooks make file reads
 * coroutine-friendly, flock() may still cause brief stalls under high write
 * concurrency. For write-heavy workloads prefer the InMemoryStorageAdapter.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SwooleServerRunner implements ServerRunnerInterface
{
    private const SOCKET_ACCEPT_TIMEOUT = 5;

    private SocketServer $server;

    private bool $isShuttingDown = false;

    public function __construct(
        private readonly ServerProtocolFactory $serverProtocolFactory,
        private readonly ?LoggerInterface $logger = null,
    ) {
        if (!extension_loaded('swoole')) {
            throw new RuntimeException(
                'The Swoole extension is required to use SwooleServerRunner. '
                . 'Install via PECL: pecl install swoole '
                . '(^5.1 for PHP 8.3/8.4, ^6.0 for PHP 8.5+)'
            );
        }
    }

    public function run(SocketServer $server): void
    {
        $this->server = $server;

        // Hook all standard PHP blocking I/O so it works inside coroutines.
        Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

        Coroutine\run(function (): void {
            $this->registerShutdownSignals();
            $this->acceptClients();
        });

        $this->logger?->info('SwooleServerRunner: all connections drained, shutdown complete.');
    }

    private function registerShutdownSignals(): void
    {
        Process::signal(SIGTERM, $this->handleShutdownSignal(...));
        Process::signal(SIGINT, $this->handleShutdownSignal(...));
        Process::signal(SIGQUIT, $this->handleShutdownSignal(...));
    }

    private function handleShutdownSignal(int $signal): void
    {
        if ($this->isShuttingDown) {
            return;
        }
        $this->isShuttingDown = true;
        $this->logger?->info(sprintf(
            'SwooleServerRunner: received signal %d, closing server.',
            $signal,
        ));
        $this->server->close();
    }

    private function acceptClients(): void
    {
        $this->logger?->info('SwooleServerRunner: accepting clients.');

        while ($this->server->isConnected()) {
            $socket = $this->server->accept(self::SOCKET_ACCEPT_TIMEOUT);

            if ($socket === null) {
                continue;
            }

            if ($this->isShuttingDown) {
                $socket->close();
                break;
            }

            Coroutine::create(function () use ($socket): void {
                $this->handleClient($socket);
            });
        }

        $this->logger?->info('SwooleServerRunner: accept loop ended, draining active connections.');
    }

    private function handleClient(Socket $socket): void
    {
        try {
            $handler = $this->serverProtocolFactory->make($socket);
            $handler->handle();
        } catch (Throwable $e) {
            $this->logger?->error(
                'SwooleServerRunner: unhandled error in client coroutine: ' . $e->getMessage()
            );
        } finally {
            $socket->close();
        }
    }
}
