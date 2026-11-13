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

namespace FreeDSx\Ldap\Container\Provider;

use Closure;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Container\ContainerReloadFactory;
use FreeDSx\Ldap\Container\Contributor\ListenerContributorInterface;
use FreeDSx\Ldap\Protocol\Queue\Budget\RequestBudget;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\CoroutineSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Initialization\Advisory\HeldRequestSizeAdvisory;
use FreeDSx\Ldap\Server\Initialization\Advisory\MemoryLimitAdvisory;
use FreeDSx\Ldap\Server\Initialization\Advisory\NoMemoryLimitAdvisory;
use FreeDSx\Ldap\Server\Initialization\Advisory\OpenFileLimitAdvisory;
use FreeDSx\Ldap\Server\Initialization\Advisory\WorkerClampAdvisory;
use FreeDSx\Ldap\Server\Initialization\AdvisoryInterface;
use FreeDSx\Ldap\Server\Initialization\Requirement\RunnerExtensionsRequirement;
use FreeDSx\Ldap\Server\Initialization\Requirement\SwooleClientCertificatesRequirement;
use FreeDSx\Ldap\Server\Initialization\ServerInitialization;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotWriter;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotFile;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotPublisher;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Recorder\MetricsRecorderChain;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Recorder\SwooleTableMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\Process\Child\ChildForker;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\Resources\SystemResources;
use FreeDSx\Ldap\Server\ServerRunner\Pcntl\MetricsRelay;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\RunnerConfiguration;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\PooledServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\ServerRunner as SwooleServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\WorkerFactory;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

/**
 * Registers the listener services shared by every server type: the socket, runner, reload, and metrics.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ServerListenerContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            SocketServerFactory::class => $this->makeSocketServerFactory(...),
            ChildForker::class => static fn(): ChildForker => new ChildForker(),
            SystemResources::class => static fn(): SystemResources => new SystemResources(),
            SleeperInterface::class => $this->makeSleeper(...),
            RequestBudget::class => static fn(Container $c): RequestBudget => new RequestBudget(
                $c->get(SleeperInterface::class),
                $c->get(SystemResources::class),
            ),
            ServerRunnerInterface::class => $this->makeServerRunner(...),
            ServerInitialization::class => $this->makeServerInitialization(...),
            InMemoryMetricsRecorder::class => static fn(): InMemoryMetricsRecorder => new InMemoryMetricsRecorder(),
            SwooleTableMetricsRecorder::class => static fn(): SwooleTableMetricsRecorder => new SwooleTableMetricsRecorder(
                SwooleTableMetricsRecorder::createTable(),
            ),
            MetricsRecorderInterface::class => $this->makeMetricsRecorder(...),
            MetricsSnapshotProvider::class => $this->makeMetricsSnapshotProvider(...),
            SnapshotFile::class => $this->makeSnapshotFile(...),
            OperationRollupCoordinator::class => $this->makeOperationRollupCoordinator(...),
        ];
    }

    private function makeSocketServerFactory(Container $container): SocketServerFactory
    {
        $options = $container->get(ServerListenerOptionsInterface::class);

        return new SocketServerFactory(
            $options->getNetworkConfig(),
            $options->getRunnerConfig()->getMode(),
            $this->makeEventLogger($options),
            $this->resolveWorkerCount($container) > 1,
        );
    }

    /**
     * The runner-appropriate sleeper: a coroutine-aware sleeper under Swoole, else a blocking one.
     */
    private function makeSleeper(Container $container): SleeperInterface
    {
        return $container->get(ServerListenerOptionsInterface::class)->isRunnerMode(RunnerMode::Swoole)
            ? new CoroutineSleeper()
            : new BlockingSleeper();
    }

    private function makeServerRunner(Container $container): ServerRunnerInterface
    {
        $options = $container->get(ServerListenerOptionsInterface::class);
        $metricsRecorder = $container->get(MetricsRecorderInterface::class);

        if ($options->isRunnerMode(RunnerMode::Swoole)) {
            $workers = $this->resolveWorkerCount($container);
            $workerFactory = new WorkerFactory(
                configuration: $this->makeRunnerConfiguration($container),
                socketServerFactory: $container->get(SocketServerFactory::class),
                metricsRecorder: $metricsRecorder,
                backgroundTasks: $container->get(BackgroundTasksInterface::class),
            );

            return $workers > 1
                ? new PooledServerRunner(
                    workerFactory: $workerFactory,
                    workers: $workers,
                    resettable: $container->get(ListenerContributorInterface::class)->forkResettable(),
                )
                : new SwooleServerRunner($workerFactory);
        }

        return new PcntlServerRunner(
            configuration: $this->makeRunnerConfiguration($container),
            socketServerFactory: $container->get(SocketServerFactory::class),
            childForker: $container->get(ChildForker::class),
            metrics: new MetricsRelay(
                $metricsRecorder,
                $this->makeSnapshotPublisher($container),
                $this->makeOperationRollup($container),
                $this->makeEventLogger($options),
            ),
            resettable: $container->get(ListenerContributorInterface::class)->forkResettable(),
            backgroundTasks: $container->get(BackgroundTasksInterface::class),
        );
    }

    private function makeRunnerConfiguration(Container $container): RunnerConfiguration
    {
        $options = $container->get(ServerListenerOptionsInterface::class);
        $buildGeneration = $this->makeGenerationBuilder($container);

        return new RunnerConfiguration(
            $options,
            $buildGeneration($options)->get(ServerProtocolFactoryInterface::class),
            self::makeReloadedProtocolFactoryProvider($buildGeneration),
            $container->get(ListenerContributorInterface::class)->applyReload(...),
        );
    }

    /**
     * The listener's requirements come first, since a runner this process cannot run leaves nothing else to check.
     */
    private function makeServerInitialization(Container $container): ServerInitialization
    {
        $options = $container->get(ServerListenerOptionsInterface::class);
        $contributor = $container->get(ListenerContributorInterface::class);

        return new ServerInitialization(
            [
                new RunnerExtensionsRequirement($options),
                new SwooleClientCertificatesRequirement($options),
                ...$contributor->requirements(),
            ],
            [
                ...$this->makeListenerAdvisories($container),
                ...$contributor->advisories(),
            ],
            $this->makeEventLogger($options),
        );
    }

    /**
     * @return list<AdvisoryInterface>
     */
    private function makeListenerAdvisories(Container $container): array
    {
        $options = $container->get(ServerListenerOptionsInterface::class);
        $network = $options->getNetworkConfig();
        $resources = $container->get(SystemResources::class);
        $contributor = $container->get(ListenerContributorInterface::class);
        $heldRequestSize = $container->get(RequestBudget::class)->limitFor($network->getMaxHeldRequestSize());

        return [
            new NoMemoryLimitAdvisory(
                $network,
                $resources->memoryLimit(),
                $heldRequestSize,
            ),
            new HeldRequestSizeAdvisory(
                $network,
                $heldRequestSize,
            ),
            new WorkerClampAdvisory(
                $options,
                $contributor->supportsMultipleWorkers(),
            ),
            new OpenFileLimitAdvisory(
                $options,
                $resources->openFileLimit(),
                $contributor->descriptorsPerClient(),
            ),
            new MemoryLimitAdvisory(
                $options,
                $resources->memoryLimit(),
                $heldRequestSize,
            ),
        ];
    }

    /**
     * The workers to actually accept on: the configured count, auto-detected from the CPUs when zero.
     *
     * This is clamped back to one when the server keeps state that cannot be shared between processes.
     */
    private function resolveWorkerCount(Container $container): int
    {
        $options = $container->get(ServerListenerOptionsInterface::class);
        if (!$options->isRunnerMode(RunnerMode::Swoole)) {
            return 1;
        }
        $workers = $options->getRunnerConfig()->resolvedWorkers();
        if ($workers === 1 || $container->get(ListenerContributorInterface::class)->supportsMultipleWorkers()) {
            return $workers;
        }

        return 1;
    }

    private function makeEventLogger(ServerListenerOptionsInterface $options): EventLogger
    {
        return new EventLogger(
            $options->getLogger(),
            $options->getEventLogPolicy(),
        );
    }

    /**
     * Assembles a fresh container from (possibly reloaded) options, carrying over the services whose state survives.
     *
     * @return Closure(ServerListenerOptionsInterface): Container
     */
    private function makeGenerationBuilder(Container $container): Closure
    {
        $rebuild = $container->get(ContainerReloadFactory::class);
        $shared = $this->reloadSharedInstances($container);

        return static fn(ServerListenerOptionsInterface $options): Container => $rebuild->rebuild(
            $options,
            $shared,
        );
    }

    /**
     * Builds a protocol factory from reloaded options, refusing options the server would refuse to start with.
     *
     * @param Closure(ServerListenerOptionsInterface): Container $buildGeneration
     * @return Closure(ServerListenerOptionsInterface): ServerProtocolFactoryInterface
     */
    private static function makeReloadedProtocolFactoryProvider(Closure $buildGeneration): Closure
    {
        return static function (
            ServerListenerOptionsInterface $options,
        ) use ($buildGeneration): ServerProtocolFactoryInterface {
            $generation = $buildGeneration($options);
            $generation->get(ServerInitialization::class)->reload();

            return $generation->get(ServerProtocolFactoryInterface::class);
        };
    }

    /**
     * Services carried verbatim across a SIGHUP reload so their live state survives into the fresh container.
     *
     * @return array<class-string, object>
     */
    private function reloadSharedInstances(Container $container): array
    {
        $shared = [
            MetricsRecorderInterface::class => $container->get(MetricsRecorderInterface::class),
            MetricsSnapshotProvider::class => $container->get(MetricsSnapshotProvider::class),
            InMemoryMetricsRecorder::class => $container->get(InMemoryMetricsRecorder::class),
            // Kept so connections from before and after a reload count against one budget.
            RequestBudget::class => $container->get(RequestBudget::class),
        ];

        // Carried so a reload keeps the one shared table rather than allocating a second, empty one.
        if ($container->get(ServerListenerOptionsInterface::class)->isRunnerMode(RunnerMode::Swoole)) {
            $shared[SwooleTableMetricsRecorder::class] = $container->get(SwooleTableMetricsRecorder::class);
        }

        $operationRollup = $this->makeOperationRollup($container);
        if ($operationRollup !== null) {
            $shared[OperationRollupCoordinator::class] = $operationRollup;
        }

        return $shared + $container->get(ListenerContributorInterface::class)->reloadInstances();
    }

    /**
     * The child-to-parent operation rollup for the forking runner; built only when cn=monitor is enabled.
     */
    private function makeOperationRollup(Container $container): ?OperationRollupCoordinator
    {
        if (!$container->get(ServerListenerOptionsInterface::class)->isMonitorEnabled()) {
            return null;
        }

        return $container->get(OperationRollupCoordinator::class);
    }

    private function makeOperationRollupCoordinator(Container $container): OperationRollupCoordinator
    {
        return new OperationRollupCoordinator($container->get(InMemoryMetricsRecorder::class));
    }

    /**
     * The PCNTL parent publishes connection metrics to a file for forked children (serving cn=monitor); built only when
     * cn=monitor is enabled.
     */
    private function makeSnapshotPublisher(Container $container): ?SnapshotPublisher
    {
        $options = $container->get(ServerListenerOptionsInterface::class);

        if (!$options->isMonitorEnabled()) {
            return null;
        }

        return new SnapshotPublisher(
            $container->get(InMemoryMetricsRecorder::class),
            new FileSnapshotWriter($container->get(SnapshotFile::class)),
        );
    }

    private function makeSnapshotFile(Container $container): SnapshotFile
    {
        $path = $container->get(ServerListenerOptionsInterface::class)->getMonitorSnapshotPath();

        return $path === null
            ? SnapshotFile::inTempDirectory()
            : SnapshotFile::at($path);
    }

    /**
     * The process metrics recorder: an in-memory recorder when cn=monitor is enabled (chained with a user recorder if
     * set), otherwise just the user recorder (a no-op by default).
     */
    private function makeMetricsRecorder(Container $container): MetricsRecorderInterface
    {
        $options = $container->get(ServerListenerOptionsInterface::class);
        $userRecorder = $options->getMetricsRecorder();

        if (!$options->isMonitorEnabled()) {
            return $userRecorder;
        }

        $recorder = $options->isRunnerMode(RunnerMode::Swoole)
            ? $container->get(SwooleTableMetricsRecorder::class)
            : $container->get(InMemoryMetricsRecorder::class);

        if ($userRecorder instanceof NullMetricsRecorder) {
            return $recorder;
        }

        return new MetricsRecorderChain(
            $recorder,
            $userRecorder,
        );
    }

    /**
     * The snapshot source for cn=monitor: the live in-memory recorder under Swoole, or the parent-published file under
     * the forking PCNTL runner.
     */
    private function makeMetricsSnapshotProvider(Container $container): MetricsSnapshotProvider
    {
        $options = $container->get(ServerListenerOptionsInterface::class);

        if (!$options->isRunnerMode(RunnerMode::Swoole)) {
            return new FileSnapshotProvider($container->get(SnapshotFile::class));
        }

        return $container->get(SwooleTableMetricsRecorder::class);
    }
}
