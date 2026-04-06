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
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketServer;
use Psr\Log\LoggerInterface;
use Swoole\Coroutine;
use Swoole\Coroutine\WaitGroup;
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
    use ServerRunnerLoggerTrait;

    /**
     * Seconds to wait for a new client before re-checking the server connection state.
     */
    private const SOCKET_ACCEPT_TIMEOUT = 0.5;

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

    /**
     * Active protocol handlers keyed by spl_object_id of their socket.
     *
     * Used to send a Notice of Disconnect to each client on shutdown.
     *
     * @var array<int, ServerProtocolHandler>
     */
    private array $activeHandlers = [];

    private WaitGroup $waitGroup;

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
        $this->waitGroup = new WaitGroup();
    }

    public function run(SocketServer $server): void
    {
        $this->server = $server;

        Coroutine\run(function (): void {
            $this->registerShutdownSignals();
            $this->acceptClients();
        });

        $this->logShutdownCompleted();
    }

    private function getRunnerLogger(): ?LoggerInterface
    {
        return $this->options->getLogger();
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
        $this->logShutdownStarted(['signal' => $signal]);
        $this->server->close();
        $this->notifyClientsOfShutdown();
        $this->startDrainTimeout();
    }

    private function notifyClientsOfShutdown(): void
    {
        foreach ($this->activeHandlers as $handler) {
            try {
                $handler->shutdown();
            } catch (Throwable $e) {
                $this->logShutdownNotifyError($e);
            }
        }
    }

    private function startDrainTimeout(): void
    {
        Coroutine::create(function (): void {
            if (empty($this->activeSockets)) {
                return;
            }

            $allClosed = $this->waitGroup->wait((float) $this->options->getShutdownTimeout());

            if ($allClosed) {
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
        $this->logServerStarted();
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
                $this->logClientRejectedDuringShutdown();
                $socket->close();
                break;
            }

            $maxConnections = $this->options->getMaxConnections();
            if ($maxConnections > 0 && count($this->activeSockets) >= $maxConnections) {
                $this->logConnectionLimitReached(['max_connections' => $maxConnections]);
                $socket->close();
                continue;
            }

            $this->waitGroup->add();
            Coroutine::create(function () use ($socket): void {
                $socketId = spl_object_id($socket);
                $this->activeSockets[$socketId] = $socket;
                try {
                    $this->handleClient($socket, $socketId);
                } finally {
                    $this->server->removeClient($socket);
                    unset($this->activeSockets[$socketId]);
                    unset($this->activeHandlers[$socketId]);
                    $this->waitGroup->done();
                }
            });
        }

        $this->options->getLogger()?->info('SwooleServerRunner: accept loop ended, draining active connections.');
    }

    private function handleClient(
        Socket $socket,
        int $socketId,
    ): void {
        try {
            $handler = $this->serverProtocolFactory->make($socket);
            $this->activeHandlers[$socketId] = $handler;
            $this->logClientConnected();
            $handler->handle();
        } catch (Throwable $e) {
            $this->options->getLogger()?->error(
                'SwooleServerRunner: unhandled error in client coroutine: ' . $e->getMessage()
            );
        } finally {
            $this->logClientClosed();
            $socket->close();
        }
    }
}
