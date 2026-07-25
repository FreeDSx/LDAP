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

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Container\Contributor\DirectoryListenerContributor;
use FreeDSx\Ldap\Container\Contributor\ListenerContributorInterface;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoBackendBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
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
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward\LdapClientForwardStateSender;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward\PasswordPolicyForwardWorker;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\Process\BackgroundTask\LongLivedTask;
use FreeDSx\Ldap\Server\Process\BackgroundTask\PcntlBackgroundTasks;
use FreeDSx\Ldap\Server\Process\BackgroundTask\PeriodicTask;
use FreeDSx\Ldap\Server\Process\BackgroundTask\SwooleBackgroundTasks;
use FreeDSx\Ldap\Server\Process\Signals\PcntlShutdownSignals;
use FreeDSx\Ldap\Server\RequestHandler\HandlerFactory;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Sync\Consumer\LdapReplica;
use FreeDSx\Ldap\Sync\Consumer\PrimaryConnectionFactory;
use Psr\Log\NullLogger;

/**
 * Registers the local-directory services.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DirectoryServerContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            HandlerFactoryInterface::class => $this->makeHandlerFactory(...),
            FilterEvaluatorInterface::class => $this->makeFilterEvaluator(...),
            EntryStorageInterface::class => $this->makeStorage(...),
            PdoBackendBuilder::class => $this->makePdoBackendBuilder(...),
            WritableStorageBackend::class => $this->makeBackend(...),
            ServerProtocolFactory::class => $this->makeServerProtocolFactory(...),
            ServerProtocolFactoryInterface::class => static fn(Container $c): ServerProtocolFactoryInterface => $c->get(ServerProtocolFactory::class),
            ServerProtocolHandlerFactory::class => $this->makeServerProtocolHandlerFactory(...),
            ClockInterface::class => static fn(): ClockInterface => new SystemClock(),
            SleeperInterface::class => $this->makeSleeper(...),
            BackgroundTasksInterface::class => $this->makeBackgroundTasks(...),
            ListenerContributorInterface::class => $this->makeListenerContributor(...),
        ];
    }

    private function makeHandlerFactory(Container $container): HandlerFactory
    {
        return new HandlerFactory(
            $container->get(ServerOptions::class),
            $container->get(WritableStorageBackend::class),
        );
    }

    private function makeFilterEvaluator(Container $container): FilterEvaluator
    {
        return new FilterEvaluator($container->get(ServerOptions::class)->getSchema());
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
            $config instanceof PdoConfig => $container->get(PdoBackendBuilder::class)->storage(),
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
     * The PDO backend assembly (storage + replica password-state store on one connection).
     */
    private function makePdoBackendBuilder(Container $container): PdoBackendBuilder
    {
        $options = $container->get(ServerOptions::class);
        $config = $options->getStorageConfig();

        if (!$config instanceof PdoConfig) {
            throw new RuntimeException('The PDO backend builder requires a PdoConfig storage config.');
        }

        return new PdoBackendBuilder(
            $config,
            $options->getRunner(),
        );
    }

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

    private function makeBackgroundTasks(Container $container): BackgroundTasksInterface
    {
        return $container->get(ServerOptions::class)->getRunner() === RunnerMode::Swoole
            ? $this->makeSwooleBackgroundTasks($container)
            : $this->makePcntlBackgroundTasks($container);
    }

    private function makeListenerContributor(Container $container): ListenerContributorInterface
    {
        $backend = $container->get(WritableStorageBackend::class);

        $instances = [
            WritableStorageBackend::class => $backend,
            EntryStorageInterface::class => $backend->getStorage(),
        ];

        // On the PDO path, share the builder so the reloaded replica store stays on the storage's connection.
        if ($container->get(ServerOptions::class)->getStorageConfig() instanceof PdoConfig) {
            $instances[PdoBackendBuilder::class] = $container->get(PdoBackendBuilder::class);
        }

        return new DirectoryListenerContributor(
            $backend,
            $instances,
        );
    }

    /**
     * The retention policy to sweep on, or null when journaling is off / has no limits.
     */
    private function journalRetentionPolicyIfSweepable(Container $container): ?RetentionPolicy
    {
        $options = $container->get(ServerOptions::class);

        if (!$options->isSyncEnabled()) {
            return null;
        }

        $journal = $container->get(WritableStorageBackend::class)->changeJournal();

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
        $journal = $container->get(WritableStorageBackend::class)->changeJournal();

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
            gracefulStopSeconds: $options->getNetworkConfig()->getShutdownTimeout(),
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
}
