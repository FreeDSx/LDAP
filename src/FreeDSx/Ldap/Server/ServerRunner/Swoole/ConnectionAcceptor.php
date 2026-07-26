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

namespace FreeDSx\Ldap\Server\ServerRunner\Swoole;

use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerLoggerTrait;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketServer;
use Psr\Log\LoggerInterface;
use Swoole\Coroutine;
use Swoole\Coroutine\WaitGroup;
use Throwable;

/**
 * Accepts clients on a bound socket, handling each in its own coroutine, and drains them on shutdown.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ConnectionAcceptor
{
    use ServerRunnerLoggerTrait;

    private SocketServer $server;

    private bool $isShuttingDown = false;

    /**
     * Active client sockets keyed by spl_object_id, to force-close what lingers past the drain timeout.
     *
     * @var array<int, Socket>
     */
    private array $activeSockets = [];

    /**
     * Active protocol handlers keyed by spl_object_id of their socket, to send each a Notice of Disconnect.
     *
     * @var array<int, ServerProtocolHandler>
     */
    private array $activeHandlers = [];

    private readonly WaitGroup $waitGroup;

    /**
     * @param ?BackgroundTasksInterface $backgroundTasks Ticked between accepts; null when this process runs none.
     */
    public function __construct(
        private ServerProtocolFactoryInterface $serverProtocolFactory,
        private ServerListenerOptionsInterface $options,
        private readonly MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
        private readonly ?BackgroundTasksInterface $backgroundTasks = null,
    ) {
        $this->waitGroup = new WaitGroup();
    }

    /**
     * Accepts clients on the bound socket until a shutdown is requested.
     */
    public function accept(SocketServer $server): void
    {
        $this->server = $server;
        $this->logServerStarted();
        $this->metricsRecorder->serverStarted(time());
        $this->options->getOnServerReady()?->__invoke();

        while (!$this->isShuttingDown) {
            $this->backgroundTasks?->tick();

            try {
                $socket = $this->server->accept($this->options->getNetworkConfig()->getSocketAcceptTimeout());
            } catch (Throwable $e) {
                $this->logAcceptError($e);

                break;
            }

            if ($socket === null) {
                continue;
            }

            if ($this->isOverConnectionLimit()) {
                $this->metricsRecorder->connectionObserved(ConnectionObservation::Rejected);
                $socket->close();
                continue;
            }

            $this->handleInCoroutine($socket);
        }

        $this->getRunnerLogger()?->info('Accept loop ended, draining active connections.');
    }

    /**
     * Stops accepting, tells connected clients the server is going away, and drains what is still in flight.
     */
    public function shutdown(): void
    {
        if ($this->isShuttingDown) {
            return;
        }

        $this->isShuttingDown = true;
        $this->server->close();
        $this->notifyClientsOfShutdown();
        $this->startDrainTimeout();
    }

    /**
     * Adopts a reloaded configuration, which subsequent connections are accepted and handled under.
     */
    public function useConfiguration(
        ServerListenerOptionsInterface $options,
        ServerProtocolFactoryInterface $serverProtocolFactory,
    ): void {
        $this->options = $options;
        $this->serverProtocolFactory = $serverProtocolFactory;
    }

    private function getRunnerLogger(): ?LoggerInterface
    {
        return $this->options->getLogger();
    }

    private function isOverConnectionLimit(): bool
    {
        $maxConnections = $this->options->getNetworkConfig()->getMaxConnections();
        if ($maxConnections <= 0 || count($this->activeSockets) < $maxConnections) {
            return false;
        }

        $this->logConnectionLimitReached(['max_connections' => $maxConnections]);

        return true;
    }

    private function handleInCoroutine(Socket $socket): void
    {
        $this->waitGroup->add();
        Coroutine::create(function () use ($socket): void {
            $socketId = spl_object_id($socket);
            $this->activeSockets[$socketId] = $socket;
            $this->metricsRecorder->connectionObserved(ConnectionObservation::Opened);

            try {
                $this->handleClient($socket, $socketId);
            } finally {
                $this->server->removeClient($socket);

                unset($this->activeSockets[$socketId]);
                unset($this->activeHandlers[$socketId]);

                $this->metricsRecorder->connectionObserved(ConnectionObservation::Closed);
                $this->waitGroup->done();
            }
        });
    }

    private function handleClient(
        Socket $socket,
        int $socketId,
    ): void {
        try {
            $handler = $this->serverProtocolFactory->make(
                $socket,
                new ConnectionContext(connId: $socketId),
            );
            $this->activeHandlers[$socketId] = $handler;
            $this->logClientConnected();
            $closeReason = $handler->handle();

            if ($closeReason !== null) {
                $this->metricsRecorder->connectionObserved($closeReason);
            }
        } catch (Throwable $e) {
            $this->logClientError($e);
        } finally {
            $this->logClientClosed();
            $socket->close();
        }
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

            $allClosed = $this->waitGroup->wait((float) $this->options->getNetworkConfig()->getShutdownTimeout());
            if ($allClosed) {
                return;
            }

            $this->logShutdownForceClose(count($this->activeSockets));
            foreach ($this->activeSockets as $socket) {
                $socket->close();
            }
        });
    }
}
