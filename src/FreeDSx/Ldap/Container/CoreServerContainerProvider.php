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

namespace FreeDSx\Ldap\Container;

use Closure;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoStorageFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Config\JsonStorageConfig;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluator;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionSweeper;
use FreeDSx\Ldap\Server\Backend\Storage\OperationalAttributeGenerator;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\CoroutineSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Clock\SystemClock;
use FreeDSx\Ldap\Server\ConnectionHandlerBuilderInterface;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotWriter;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotPublisher;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Recorder\MetricsRecorderChain;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward\LdapClientForwardStateSender;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward\PasswordPolicyForwardWorker;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\Process\BackgroundTask\LongLivedTask;
use FreeDSx\Ldap\Server\Process\BackgroundTask\PcntlBackgroundTasks;
use FreeDSx\Ldap\Server\Process\BackgroundTask\PeriodicTask;
use FreeDSx\Ldap\Server\Process\BackgroundTask\SwooleBackgroundTasks;
use FreeDSx\Ldap\Server\Process\Signals\PcntlShutdownSignals;
use FreeDSx\Ldap\Server\Proxy\ProxyProtocolFactory;
use FreeDSx\Ldap\Server\RequestHandler\HandlerFactory;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\ServerRunner\SwooleServerRunner;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Sync\Consumer\LdapReplica;
use FreeDSx\Ldap\Sync\Consumer\PrimaryConnectionFactory;
use Psr\Log\NullLogger;

/**
 * Registers the core server services: sockets, backend, protocol factory, runner, metrics, and clock.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class CoreServerContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            SocketServerFactory::class => $this->makeSocketServerFactory(...),
            HandlerFactoryInterface::class => $this->makeHandlerFactory(...),
            FilterEvaluatorInterface::class => $this->makeFilterEvaluator(...),
            EntryStorageInterface::class => $this->makeStorage(...),
            WritableStorageBackend::class => $this->makeBackend(...),
            ServerProtocolFactory::class => $this->makeServerProtocolFactory(...),
            ServerProtocolFactoryInterface::class => $this->makeServerProtocolFactoryInterface(...),
            ServerRunnerInterface::class => $this->makeServerRunner(...),
            ServerAuthorization::class => $this->makeServerAuthorizer(...),
            ClockInterface::class => static fn(): ClockInterface => new SystemClock(),
            SleeperInterface::class => $this->makeSleeper(...),
            ServerProtocolHandlerFactory::class => $this->makeServerProtocolHandlerFactory(...),
            InMemoryMetricsRecorder::class => static fn(): InMemoryMetricsRecorder => new InMemoryMetricsRecorder(),
            MetricsRecorderInterface::class => $this->makeMetricsRecorder(...),
            MetricsSnapshotProvider::class => $this->makeMetricsSnapshotProvider(...),
            OperationRollupCoordinator::class => $this->makeOperationRollupCoordinator(...),
        ];
    }

    private function makeSocketServerFactory(Container $container): SocketServerFactory
    {
        $serverOptions = $container->get(ServerOptions::class);

        return new SocketServerFactory(
            options: $serverOptions,
            logger: $serverOptions->getLogger(),
        );
    }

    private function makeServerAuthorizer(Container $container): ServerAuthorization
    {
        return new ServerAuthorization($container->get(ServerOptions::class));
    }

    private function makeServerProtocolHandlerFactory(Container $container): ServerProtocolHandlerFactory
    {
        return new ServerProtocolHandlerFactory($container->get(ServerOptions::class));
    }

    /**
     * The runner-appropriate sleeper: a coroutine-aware sleeper under Swoole, else a blocking one.
     */
    private function makeSleeper(Container $container): SleeperInterface
    {
        return $container->get(ServerOptions::class)->getRunner() === RunnerMode::Swoole
            ? new CoroutineSleeper()
            : new BlockingSleeper();
    }

    private function makeHandlerFactory(Container $container): HandlerFactory
    {
        return new HandlerFactory(
            $container->get(ServerOptions::class),
            $this->backendOrFail($container),
        );
    }

    private function makeFilterEvaluator(Container $container): FilterEvaluator
    {
        return new FilterEvaluator($container->get(ServerOptions::class)->getSchema());
    }

    /**
     * The configured backend; only reached on the non-proxy path, where LdapServer's startup check guarantees one.
     */
    private function backendOrFail(Container $container): WritableStorageBackend
    {
        return $this->backendOrNull($container)
            ?? throw new RuntimeException('No storage is configured; set ServerOptions::setStorageConfig().');
    }

    /**
     * The assembled backend, or null on the proxy path which serves no local directory.
     */
    private function backendOrNull(Container $container): ?WritableStorageBackend
    {
        return $container->has(ProxyOptions::class)
            ? null
            : $container->get(WritableStorageBackend::class);
    }

    /**
     * Build the runner-appropriate storage backend from the configured StorageConfigInterface.
     */
    private function makeStorage(Container $container): EntryStorageInterface
    {
        $options = $container->get(ServerOptions::class);
        $config = $options->getStorageConfig();
        $swoole = $options->getRunner() === RunnerMode::Swoole;

        return match (true) {
            $config instanceof PdoConfig => $swoole
                ? PdoStorageFactory::forSwoole($config)
                : PdoStorageFactory::forPcntl($config),
            $config instanceof JsonStorageConfig => $swoole
                ? JsonFileStorage::forSwoole(
                    $config->path(),
                    logger: $config->logger(),
                )
                : JsonFileStorage::forPcntl(
                    $config->path(),
                    logger: $config->logger(),
                ),
            $config instanceof InMemoryStorageConfig => new InMemoryStorage($config->entries()),
            default => throw new RuntimeException(sprintf(
                'Unsupported storage config "%s".',
                $config::class,
            )),
        };
    }

    /**
     * Assemble the writable backend from the container-built storage; only invoked when storage is configured.
     */
    private function makeBackend(Container $container): WritableStorageBackend
    {
        $options = $container->get(ServerOptions::class);
        $storage = $container->get(EntryStorageInterface::class);

        $schema = $options->getSchemaValidationMode() !== SchemaValidationMode::Off
            ? $options->getSchema()
            : null;

        return new WritableStorageBackend(
            storage: $storage,
            limits: $options->makeSearchLimits(),
            validator: $this->buildSchemaValidator($container),
            operationalAttrs: new OperationalAttributeGenerator($schema),
            changeRecorder: $this->changeRecorderFor($container, $storage),
            schema: $options->getSchema(),
        );
    }

    private function buildSchemaValidator(Container $container): ?SchemaValidator
    {
        $options = $container->get(ServerOptions::class);
        $mode = $options->getSchemaValidationMode();

        if ($mode === SchemaValidationMode::Off) {
            return null;
        }

        return new SchemaValidator(
            $options->getSchema(),
            $mode,
        );
    }

    /**
     * Configure the storage's journal and return a recorder when sync is enabled and the storage can journal.
     */
    private function changeRecorderFor(
        Container $container,
        EntryStorageInterface $storage,
    ): ?ChangeRecorder {
        $options = $container->get(ServerOptions::class);

        if (!$options->isSyncEnabled() || !$storage instanceof ChangeJournalingInterface) {
            return null;
        }

        $storage->configureJournal($options->getChangeJournalConfig());

        return new ChangeRecorder($options->getLogger() ?? new NullLogger());
    }

    private function makeServerProtocolFactory(Container $container): ServerProtocolFactory
    {
        return new ServerProtocolFactory($container->get(ConnectionHandlerBuilderInterface::class));
    }

    private function makeServerProtocolFactoryInterface(Container $container): ServerProtocolFactoryInterface
    {
        if ($container->has(ProxyOptions::class)) {
            return new ProxyProtocolFactory(
                $container->get(ServerOptions::class),
                $container->get(ProxyOptions::class),
            );
        }

        return $container->get(ServerProtocolFactory::class);
    }

    private function makeServerRunner(Container $container): ServerRunnerInterface
    {
        $options = $container->get(ServerOptions::class);
        $protocolFactoryProvider = $this->makeProtocolFactoryProvider($container);
        $metricsRecorder = $container->get(MetricsRecorderInterface::class);

        if ($options->getRunner() === RunnerMode::Swoole) {
            return new SwooleServerRunner(
                serverProtocolFactory: $protocolFactoryProvider($options),
                options: $options,
                socketServerFactory: $container->get(SocketServerFactory::class),
                protocolFactoryProvider: $protocolFactoryProvider,
                metricsRecorder: $metricsRecorder,
                backgroundTasks: $this->makeSwooleBackgroundTasks($container),
            );
        }

        return new PcntlServerRunner(
            serverProtocolFactory: $protocolFactoryProvider($options),
            options: $options,
            socketServerFactory: $container->get(SocketServerFactory::class),
            protocolFactoryProvider: $protocolFactoryProvider,
            metricsRecorder: $metricsRecorder,
            snapshotPublisher: $this->makeSnapshotPublisher($container),
            operationRollup: $this->makeOperationRollup($container),
            backend: $this->backendOrNull($container),
            backgroundTasks: $this->makePcntlBackgroundTasks($container),
        );
    }

    /**
     * The retention policy to sweep on, or null when journaling is off / has no limits.
     */
    private function journalRetentionPolicyIfSweepable(Container $container): ?RetentionPolicy
    {
        $options = $container->get(ServerOptions::class);
        $backend = $this->backendOrNull($container);

        if ($backend === null || !$options->isSyncEnabled()) {
            return null;
        }

        $journal = $backend->changeJournal();

        if ($journal === null) {
            return null;
        }

        $policy = $options->getChangeJournalConfig()->retention;

        return RetentionSweeper::isSweepable(
            $policy,
            $journal,
            $options->getRunner() === RunnerMode::Swoole,
        )
            ? $policy
            : null;
    }

    private function makeRetentionSweeper(Container $container): ?RetentionSweeper
    {
        $policy = $this->journalRetentionPolicyIfSweepable($container);

        if ($policy === null) {
            return null;
        }

        // Safe to resolve now: a non-null policy means sync is enabled and the journal is configured.
        $journal = $this->backendOrNull($container)?->changeJournal();

        if ($journal === null) {
            return null;
        }

        $options = $container->get(ServerOptions::class);

        return new RetentionSweeper(
            $journal,
            $policy,
            new EventLogger(
                $options->getLogger(),
                $options->getEventLogPolicy(),
            ),
        );
    }

    private function makeSwooleBackgroundTasks(Container $container): SwooleBackgroundTasks
    {
        $periodicTasks = [];
        $sweeper = $this->makeRetentionSweeper($container);
        if ($sweeper !== null) {
            $periodicTasks[] = new PeriodicTask(
                RetentionSweeper::TASK_NAME,
                RetentionSweeper::DEFAULT_INTERVAL_SECONDS,
                static function () use ($sweeper): void {
                    $sweeper->sweep();
                },
            );
        }

        $longLivedTasks = [];
        $daemon = $this->makeReplicaDaemon($container, hostManagedShutdown: true);
        if ($daemon !== null) {
            $longLivedTasks[] = new LongLivedTask(
                LdapReplica::TASK_NAME,
                $daemon->run(...),
                $daemon->stop(...),
            );
        }
        $forwardWorker = $this->makeForwardWorker($container, useCoroutineSleeper: true);
        if ($forwardWorker !== null) {
            $longLivedTasks[] = new LongLivedTask(
                PasswordPolicyForwardWorker::TASK_NAME,
                $forwardWorker->run(...),
                $forwardWorker->stop(...),
            );
        }

        return new SwooleBackgroundTasks(
            $periodicTasks,
            $longLivedTasks,
            $container->get(ServerOptions::class)->getLogger(),
        );
    }

    private function makePcntlBackgroundTasks(Container $container): PcntlBackgroundTasks
    {
        $options = $container->get(ServerOptions::class);

        $periodicTasks = [];
        if ($this->journalRetentionPolicyIfSweepable($container) !== null) {
            $periodicTasks[] = new PeriodicTask(
                RetentionSweeper::TASK_NAME,
                RetentionSweeper::DEFAULT_INTERVAL_SECONDS,
                function () use ($container): void {
                    $this->makeRetentionSweeper($container)?->sweep();
                },
            );
        }

        $longLivedTasks = [];
        if ($options->getReplicaConfig() !== null) {
            $longLivedTasks[] = new LongLivedTask(
                LdapReplica::TASK_NAME,
                function () use ($container): void {
                    $this->makeReplicaDaemon($container, hostManagedShutdown: false)?->run();
                },
            );
        }
        if ($this->makeForwardWorker($container, useCoroutineSleeper: false) !== null) {
            $longLivedTasks[] = new LongLivedTask(
                PasswordPolicyForwardWorker::TASK_NAME,
                function () use ($container): void {
                    $this->makeForwardWorker($container, useCoroutineSleeper: false)?->run();
                },
            );
        }

        return new PcntlBackgroundTasks(
            periodicTasks: $periodicTasks,
            longLivedTasks: $longLivedTasks,
            logger: $options->getLogger(),
            gracefulStopSeconds: $options->getShutdownTimeout(),
        );
    }

    /**
     * The replica password-policy forward worker when replica mode + password policy are configured, else null.
     */
    private function makeForwardWorker(
        Container $container,
        bool $useCoroutineSleeper,
    ): ?PasswordPolicyForwardWorker {
        $options = $container->get(ServerOptions::class);
        $config = $options->getReplicaConfig();

        if ($config === null || !$options->isPasswordPolicyEnabled()) {
            return null;
        }

        return new PasswordPolicyForwardWorker(
            $container->get(ReplicaPasswordStateStoreInterface::class),
            new LdapClientForwardStateSender(new PrimaryConnectionFactory($config)),
            $container->get(SleeperInterface::class),
            signals: $useCoroutineSleeper
                ? null
                : new PcntlShutdownSignals(),
            logger: $options->getLogger(),
        );
    }

    /**
     * The replica sync daemon when replica mode is configured, else null.
     *
     * @param bool $hostManagedShutdown true under Swoole (the runner calls stop()), false under PCNTL (the forked child owns its signals)
     */
    private function makeReplicaDaemon(
        Container $container,
        bool $hostManagedShutdown,
    ): ?LdapReplica {
        $options = $container->get(ServerOptions::class);
        $config = $options->getReplicaConfig();

        if ($config === null) {
            return null;
        }

        $storage = $container->get(EntryStorageInterface::class);

        // Pair reconciliation with forwarding: the store drops forwarded state once the primary's entry replicates back.
        $passwordStateStore = $options->isPasswordPolicyEnabled()
            ? $container->get(ReplicaPasswordStateStoreInterface::class)
            : null;

        return $hostManagedShutdown
            ? LdapReplica::forSwoole(
                $config,
                $storage,
                $options->getLogger(),
                signals: null,
                passwordStateStore: $passwordStateStore,
            )
            : LdapReplica::forPcntl(
                $config,
                $storage,
                $options->getLogger(),
                passwordStateStore: $passwordStateStore,
            );
    }

    /**
     * The child-to-parent operation rollup for the forking runner, over the shared in-memory recorder; built only when
     * cn=monitor is enabled.
     */
    private function makeOperationRollup(Container $container): ?OperationRollupCoordinator
    {
        if (!$container->get(ServerOptions::class)->isMonitorEnabled()) {
            return null;
        }

        return $container->get(OperationRollupCoordinator::class);
    }

    private function makeOperationRollupCoordinator(Container $container): OperationRollupCoordinator
    {
        return new OperationRollupCoordinator($container->get(InMemoryMetricsRecorder::class));
    }

    /**
     * The PCNTL parent publishes connection metrics to a file for forked children (serving cn=monitor) to read; built
     * only when cn=monitor is enabled.
     */
    private function makeSnapshotPublisher(Container $container): ?SnapshotPublisher
    {
        $options = $container->get(ServerOptions::class);

        if (!$options->isMonitorEnabled()) {
            return null;
        }

        return new SnapshotPublisher(
            $container->get(InMemoryMetricsRecorder::class),
            new FileSnapshotWriter($options->getMonitorSnapshotPath()),
        );
    }

    /**
     * The process metrics recorder: an in-memory recorder when cn=monitor is enabled (chained with a user recorder if
     * set), otherwise just the user recorder (a no-op by default).
     */
    private function makeMetricsRecorder(Container $container): MetricsRecorderInterface
    {
        $options = $container->get(ServerOptions::class);
        $userRecorder = $options->getMetricsRecorder();

        if (!$options->isMonitorEnabled()) {
            return $userRecorder;
        }

        $inMemory = $container->get(InMemoryMetricsRecorder::class);

        if ($userRecorder instanceof NullMetricsRecorder) {
            return $inMemory;
        }

        return new MetricsRecorderChain(
            $inMemory,
            $userRecorder,
        );
    }

    /**
     * The snapshot source for cn=monitor: the live in-memory recorder under Swoole, or the parent-published file under
     * the forking PCNTL runner.
     */
    private function makeMetricsSnapshotProvider(Container $container): MetricsSnapshotProvider
    {
        $options = $container->get(ServerOptions::class);

        if ($options->getRunner() !== RunnerMode::Swoole) {
            return new FileSnapshotProvider($options->getMonitorSnapshotPath());
        }

        return $container->get(InMemoryMetricsRecorder::class);
    }

    /**
     * Builds a protocol factory from a (possibly reloaded) set of options via a fresh container.
     *
     * @return Closure(ServerOptions): ServerProtocolFactoryInterface
     */
    private function makeProtocolFactoryProvider(Container $container): Closure
    {
        $proxyOptions = $container->has(ProxyOptions::class)
            ? $container->get(ProxyOptions::class)
            : null;
        // Carry the backend and its storage across reloads so a SIGHUP does not drop or rebuild the configured storage;
        // sharing the exact instance keeps the backend, replica daemon, and replica ppolicy store on one storage.
        $backend = $this->backendOrNull($container);
        $storage = $backend?->getStorage();

        // Share the metrics state across reloads so SIGHUP does not reset the counters or detach cn=monitor. The rollup
        // coordinator is shared so a reloaded middleware streams to the same channel the (persistent) runner bound.
        $metricsRecorder = $container->get(MetricsRecorderInterface::class);
        $metricsSnapshots = $container->get(MetricsSnapshotProvider::class);
        $inMemoryMetrics = $container->get(InMemoryMetricsRecorder::class);
        $operationRollup = $this->makeOperationRollup($container);

        return static function (ServerOptions $options) use (
            $proxyOptions,
            $backend,
            $metricsRecorder,
            $metricsSnapshots,
            $inMemoryMetrics,
            $operationRollup,
        ): ServerProtocolFactoryInterface {
            $sharedInstances = [
                MetricsRecorderInterface::class => $metricsRecorder,
                MetricsSnapshotProvider::class => $metricsSnapshots,
                InMemoryMetricsRecorder::class => $inMemoryMetrics,
            ];

            if ($backend !== null) {
                $sharedInstances[WritableStorageBackend::class] = $backend;
            }

            if ($operationRollup !== null) {
                $sharedInstances[OperationRollupCoordinator::class] = $operationRollup;
            }

            $container = $proxyOptions !== null
                ? Container::forProxy(
                    $options,
                    $proxyOptions,
                    $sharedInstances,
                )
                : Container::forServer(
                    $options,
                    $sharedInstances,
                );

            return $container->get(ServerProtocolFactoryInterface::class);
        };
    }
}
