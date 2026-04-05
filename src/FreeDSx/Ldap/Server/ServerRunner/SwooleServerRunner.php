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
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketServer;
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
    /**
     * Seconds to wait for a new client before re-checking the server connection state.
     */
    private const SOCKET_ACCEPT_TIMEOUT = 1;

    private SocketServer $server;

    private bool $isShuttingDown = false;

    /**
     * Active client sockets keyed by spl_object_id.
     *
     * Used to force-close lingering connections when the drain timeout expires.
     *
     * @var array<int, Socket>
     */
    private array $activeSockets = [];

    public function __construct(
        private readonly ServerProtocolFactory $serverProtocolFactory,
        private readonly ServerOptions $options,
    ) {
        if (!extension_loaded('swoole')) {
            throw new RuntimeException(
                'The Swoole extension is required to use SwooleServerRunner. '
                . 'Install via PECL: pecl install swoole '
                . '(^5.1 for PHP 8.3/8.4, ^6.0 for PHP 8.5+)'
            );
        }

        // Enable coroutine hooks before any socket is created so that
        // stream_socket_accept (and related functions) are coroutine-aware
        // for the server socket that makeAndBind() is about to create.
        Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    }

    public function run(SocketServer $server): void
    {
        $this->server = $server;

        Coroutine\run(function (): void {
            $this->registerShutdownSignals();
            $this->acceptClients();
        });

        $this->options->getLogger()?->info('SwooleServerRunner: all connections drained, shutdown complete.');
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
        $this->options->getLogger()?->info(sprintf(
            'SwooleServerRunner: received signal %d, closing server.',
            $signal,
        ));
        $this->server->close();
        $this->startDrainTimeout();
    }

    private function startDrainTimeout(): void
    {
        Coroutine::create(function (): void {
            if (empty($this->activeSockets)) {
                return;
            }

            Coroutine::sleep($this->options->getShutdownTimeout());

            if (empty($this->activeSockets)) {
                return;
            }

            $this->options->getLogger()?->warning(sprintf(
                'SwooleServerRunner: shutdown timeout (%d s) exceeded with %d active connection(s), forcing close.',
                $this->options->getShutdownTimeout(),
                count($this->activeSockets),
            ));

            foreach ($this->activeSockets as $socket) {
                $socket->close();
            }
        });
    }

    private function acceptClients(): void
    {
        $this->options->getLogger()?->info('SwooleServerRunner: accepting clients.');
        $this->options->getOnServerReady()?->__invoke();

        while ($this->server->isConnected()) {
            try {
                $socket = $this->server->accept(self::SOCKET_ACCEPT_TIMEOUT);
            } catch (Throwable $e) {
                $this->options->getLogger()?->error(
                    'SwooleServerRunner: accept() failed: ' . $e->getMessage()
                );
                break;
            }

            if ($socket === null) {
                continue;
            }

            if ($this->isShuttingDown) {
                $socket->close();
                break;
            }

            $maxConnections = $this->options->getMaxConnections();
            if ($maxConnections > 0 && count($this->activeSockets) >= $maxConnections) {
                $this->options->getLogger()?->warning(sprintf(
                    'SwooleServerRunner: connection limit (%d) reached, dropping new connection.',
                    $maxConnections,
                ));
                $socket->close();
                continue;
            }

            Coroutine::create(function () use ($socket): void {
                $socketId = spl_object_id($socket);
                $this->activeSockets[$socketId] = $socket;
                try {
                    $this->handleClient($socket);
                } finally {
                    $this->server->removeClient($socket);
                    unset($this->activeSockets[$socketId]);
                }
            });
        }

        $this->options->getLogger()?->info('SwooleServerRunner: accept loop ended, draining active connections.');
    }

    private function handleClient(Socket $socket): void
    {
        try {
            $handler = $this->serverProtocolFactory->make($socket);
            $handler->handle();
        } catch (Throwable $e) {
            $this->options->getLogger()?->error(
                'SwooleServerRunner: unhandled error in client coroutine: ' . $e->getMessage()
            );
        } finally {
            $socket->close();
        }
    }
}
