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

use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\WorkerScopedMetricsInterface;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerLoggerTrait;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared\ConnectionSlots;
use FreeDSx\Ldap\Server\SocketServerFactory;
use Psr\Log\LoggerInterface;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Process;
use Swoole\Runtime;

/**
 * One coroutine process serving its own listening socket.
 *
 * A single-process runner is one of these and a pooled runner is several (each in its own worker process).
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Worker
{
    use ServerRunnerLoggerTrait;

    private const AWAIT_RELOAD_POLL_SECONDS = 1.0;

    private ?ConnectionAcceptor $acceptor = null;

    private bool $isShuttingDown = false;

    /**
     * @var ?Channel<bool>
     */
    private ?Channel $awaitingReload = null;

    /**
     * @param ?BackgroundTasksInterface $backgroundTasks Null for a worker that does not run them, since they must run once.
     * @param int $workerId The pool's id for this worker. 0 for a single process.
     */
    public function __construct(
        private readonly WorkerConfiguration $configuration,
        private readonly SocketServerFactory $socketServerFactory,
        private readonly ConnectionSlots $connectionSlots,
        private readonly MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
        private readonly ?BackgroundTasksInterface $backgroundTasks = null,
        private readonly int $workerId = 0,
    ) {}

    /**
     * Serves connections until a shutdown signal, then drains what is still in flight.
     */
    public function run(): void
    {
        $context = ['worker_id' => $this->workerId];

        Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
        $isAdopted = $this->configuration->adoptOnStart($context);
        $this->claimWorkerMetrics();
        $this->connectionSlots->claimWorker($this->workerId);

        Coroutine\run(function () use ($isAdopted, $context): void {
            $this->registerShutdownSignals($context);

            if ($isAdopted || $this->awaitReload()) {
                $this->serve();
            }
        });

        $this->logShutdownCompleted($context);
    }

    /**
     * Nothing yields between publishing the acceptor and accepting, so a shutdown signal always finds it listening.
     */
    private function serve(): void
    {
        if ($this->isShuttingDown) {
            return;
        }

        $acceptor = new ConnectionAcceptor(
            $this->configuration->protocolFactory(),
            $this->configuration->options(),
            $this->socketServerFactory->isTlsHandshakeDeferred(),
            $this->connectionSlots,
            $this->metricsRecorder,
            $this->backgroundTasks,
        );

        // The socket must be bound inside the coroutine for Swoole to hook stream_socket_accept() as yielding.
        $server = $this->socketServerFactory->makeAndBind();
        $this->backgroundTasks?->start();
        $this->acceptor = $acceptor;
        $acceptor->accept($server);
    }

    /**
     * Waits unbound, so the pool sends this worker no connections, until a reload succeeds or a shutdown ends the wait.
     */
    private function awaitReload(): bool
    {
        $this->awaitingReload = new Channel(1);

        // A bounded pop keeps a timer pending, so Swoole never mistakes the wait for a deadlock.
        while (!$this->isShuttingDown) {
            if ($this->awaitingReload->pop(self::AWAIT_RELOAD_POLL_SECONDS) === true) {
                $this->awaitingReload = null;

                return true;
            }
        }
        $this->awaitingReload = null;

        return false;
    }

    private function resumeAwaitingReload(bool $isAdopted): void
    {
        $channel = $this->awaitingReload;
        if ($channel === null) {
            return;
        }

        Coroutine::create(static function () use ($channel, $isAdopted): void {
            $channel->push($isAdopted);
        });
    }

    /**
     * A worker the pool restarts reuses its id, so claiming it here discards what its predecessor left behind.
     */
    private function claimWorkerMetrics(): void
    {
        if (!$this->metricsRecorder instanceof WorkerScopedMetricsInterface) {
            return;
        }

        $this->metricsRecorder->beginWorker($this->workerId);
    }

    private function getRunnerLogger(): ?LoggerInterface
    {
        return $this->configuration->options()->getLogger();
    }

    /**
     * @param array<string, scalar> $context
     */
    private function registerShutdownSignals(array $context): void
    {
        Process::signal(
            SIGTERM,
            fn(int $signal): null => $this->handleShutdownSignal($signal, $context),
        );
        Process::signal(
            SIGINT,
            fn(int $signal): null => $this->handleShutdownSignal($signal, $context),
        );
        Process::signal(
            SIGQUIT,
            fn(int $signal): null => $this->handleShutdownSignal($signal, $context),
        );
        Process::signal(
            SIGHUP,
            fn(int $signal): null => $this->handleReloadSignal($signal, $context),
        );
    }

    /**
     * Workers reload independently, so one that fails keeps serving the configuration it already had.
     *
     * @param array<string, scalar> $context
     */
    private function handleReloadSignal(
        int $signal,
        array $context,
    ): null {
        if (!$this->configuration->reload($context + ['signal' => $signal])) {
            return null;
        }

        $this->metricsRecorder->serverReloaded(time());
        $this->acceptor?->useConfiguration(
            $this->configuration->options(),
            $this->configuration->protocolFactory(),
        );
        $this->resumeAwaitingReload(true);

        return null;
    }

    /**
     * @param array<string, scalar> $context
     */
    private function handleShutdownSignal(
        int $signal,
        array $context,
    ): null {
        if ($this->isShuttingDown) {
            return null;
        }

        $this->isShuttingDown = true;
        $this->resumeAwaitingReload(false);
        $this->backgroundTasks?->stop();
        $this->logShutdownStarted($context + ['signal' => $signal]);

        // Notifying clients writes through hooked I/O, which Swoole refuses outside a coroutine, and a pool
        // worker runs this callback without one.
        Coroutine::create(function (): void {
            $this->acceptor?->shutdown();
        });

        return null;
    }
}
