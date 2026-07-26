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

use Closure;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\ReloadsConfigurationTrait;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerLoggerTrait;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Ldap\ServerOptions;
use Psr\Log\LoggerInterface;
use Swoole\Coroutine;
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
    use ReloadsConfigurationTrait;

    private ?ConnectionAcceptor $acceptor = null;

    private bool $isShuttingDown = false;

    /**
     * @param ?BackgroundTasksInterface $backgroundTasks Null for a worker that does not run them, since they must run once.
     */
    public function __construct(
        ServerProtocolFactoryInterface $serverProtocolFactory,
        ServerListenerOptionsInterface $options,
        private readonly SocketServerFactory $socketServerFactory,
        Closure $protocolFactoryProvider,
        private readonly MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
        private readonly ?BackgroundTasksInterface $backgroundTasks = null,
    ) {
        $this->serverProtocolFactory = $serverProtocolFactory;
        $this->options = $options;
        $this->protocolFactoryProvider = $protocolFactoryProvider;
    }

    /**
     * Serves connections until a shutdown signal, then drains what is still in flight.
     *
     * @param array<string, scalar> $context Added to this worker's lifecycle log entries.
     */
    public function run(array $context = []): void
    {
        Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
        $this->adoptCurrentConfiguration($context);

        $acceptor = new ConnectionAcceptor(
            $this->serverProtocolFactory,
            $this->options,
            $this->metricsRecorder,
            $this->backgroundTasks,
        );
        $this->acceptor = $acceptor;

        // The socket must be bound inside the coroutine for Swoole to hook stream_socket_accept() as yielding.
        Coroutine\run(function () use ($acceptor, $context): void {
            $server = $this->socketServerFactory->makeAndBind();
            $this->registerShutdownSignals($context);
            $this->backgroundTasks?->start();
            $acceptor->accept($server);
        });

        $this->logShutdownCompleted($context);
    }

    /**
     * Keeps a worker respawned after a crash on the configuration its siblings already reloaded.
     *
     * @param array<string, scalar> $context
     */
    private function adoptCurrentConfiguration(array $context): void
    {
        if (!$this->options instanceof ServerOptions || $this->options->getConfigReloader() === null) {
            return;
        }

        $this->reloadConfiguration($context);
    }

    private function getRunnerLogger(): ?LoggerInterface
    {
        return $this->options->getLogger();
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
        $this->metricsRecorder->serverReloaded(time());
        $this->reloadConfiguration($context + ['signal' => $signal]);
        $this->acceptor?->useConfiguration(
            $this->options,
            $this->serverProtocolFactory,
        );

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
        $this->backgroundTasks?->stop();
        $this->logShutdownStarted($context + ['signal' => $signal]);
        $this->acceptor?->shutdown();

        return null;
    }
}
