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
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\ConfidentialAttributeAccessControl;
use FreeDSx\Ldap\Server\AccessControl\ConfidentialAttributePolicy;
use FreeDSx\Ldap\Server\AccessControl\PrivilegedBypassAccessControl;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\CoroutineLock;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\FileLock;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoBackendBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Config\JsonStorageConfig;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DirectoryDumper;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestReplayer;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluator;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditingChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\FileChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionSweeper;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use FreeDSx\Ldap\Server\Backend\Storage\OperationalAttributeGenerator;
use FreeDSx\Ldap\Server\Backend\Storage\SearchStreamBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptionsFactory;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\CoroutineSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Clock\SystemClock;
use FreeDSx\Ldap\Server\ConnectionHandlerBuilderInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\AttributeSearchBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverChain;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\DnBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticator;
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
    private const JOURNAL_SUFFIX = '.journal.jsonl';

    private const SEQ_SUFFIX = '.journal.seq';

    public function factories(): array
    {
        return [
            AccessControlInterface::class => $this->makeAccessControl(...),
            BindNameResolverInterface::class => $this->makeIdentityResolverChain(...),
            PasswordAuthenticatableInterface::class => $this->makePasswordAuthenticator(...),
            FilterEvaluatorInterface::class => $this->makeFilterEvaluator(...),
            EntryStorageInterface::class => $this->makeStorage(...),
            DirectoryDumper::class => $this->makeDirectoryDumper(...),
            OperationalAttributeGenerator::class => $this->makeOperationalAttributeGenerator(...),
            SearchStreamBuilder::class => $this->makeSearchStreamBuilder(...),
            LdapImporter::class => $this->makeLdapImporter(...),
            PdoBackendBuilder::class => $this->makePdoBackendBuilder(...),
            WritableStorageBackend::class => $this->makeBackend(...),
            WriteRequestReplayer::class => $this->makeWriteRequestReplayer(...),
            ServerProtocolFactory::class => $this->makeServerProtocolFactory(...),
            ServerProtocolFactoryInterface::class => static fn(Container $c): ServerProtocolFactoryInterface => $c->get(ServerProtocolFactory::class),
            ServerProtocolHandlerFactory::class => $this->makeServerProtocolHandlerFactory(...),
            ClockInterface::class => static fn(): ClockInterface => new SystemClock(),
            SleeperInterface::class => $this->makeSleeper(...),
            BackgroundTasksInterface::class => $this->makeBackgroundTasks(...),
            ListenerContributorInterface::class => $this->makeListenerContributor(...),
        ];
    }

    /**
     * The configured policy, wrapped so a privileged token bypasses it and confidential attributes are withheld.
     */
    private function makeAccessControl(Container $container): AccessControlInterface
    {
        $options = $container->get(ServerOptions::class);
        $configured = $options->getAccessControl();

        $acl = new PrivilegedBypassAccessControl(new ConfidentialAttributeAccessControl(
            $configured,
            new ConfidentialAttributePolicy(
                $configured,
                $options->getSchema(),
            ),
        ));

        // Both wrappers pass this inward, so the configured policy is the one that actually receives it.
        $acl->setBackend($container->get(WritableStorageBackend::class));

        return $acl;
    }

    /**
     * The configured resolver behind a DN resolver, which wins whenever the bind name already is a DN.
     */
    private function makeIdentityResolverChain(Container $container): BindNameResolverInterface
    {
        $configured = $container->get(ServerOptions::class)->getIdentityResolver();

        return new BindNameResolverChain([
            new DnBindNameResolver(),
            $configured ?? new AttributeSearchBindNameResolver(),
        ]);
    }

    /**
     * The configured authenticator, else one reading userPassword from entries the backend returns.
     */
    private function makePasswordAuthenticator(Container $container): PasswordAuthenticatableInterface
    {
        return $container->get(ServerOptions::class)->getPasswordAuthenticator()
            ?? new PasswordAuthenticator(
                $container->get(BindNameResolverInterface::class),
                $container->get(WritableStorageBackend::class),
            );
    }

    private function makeFilterEvaluator(Container $container): FilterEvaluator
    {
        $options = $container->get(ServerOptions::class);

        return new FilterEvaluator(
            $options->getSchema(),
            $options->getSubschemaEntry(),
        );
    }

    private function makeWriteRequestReplayer(Container $container): WriteRequestReplayer
    {
        return new WriteRequestReplayer($container->get(WritableStorageBackend::class));
    }

    private function makeDirectoryDumper(Container $container): DirectoryDumper
    {
        $storage = $container->get(EntryStorageInterface::class);

        return new DirectoryDumper(
            $storage,
            $storage->namingContexts(),
            $container->get(FilterEvaluatorInterface::class),
        );
    }

    /**
     * Build the runner-appropriate storage backend from the configured StorageConfigInterface.
     */
    private function makeStorage(Container $container): EntryStorageInterface
    {
        $config = $container->get(ServerOptions::class)->getStorageConfig();
        $journalConfig = $this->journalConfig($container);
        $origin = $this->journalOrigin($container);

        return match (true) {
            $config instanceof PdoConfig => $container->get(PdoBackendBuilder::class)->storage(),
            $config instanceof JsonStorageConfig => $this->makeJsonStorage(
                $container,
                $config,
                $journalConfig,
            ),
            $config instanceof InMemoryStorageConfig => new InMemoryStorage(
                $config->entries(),
                $journalConfig === null ? null : AuditingChangeJournal::wrap(
                    new InMemoryChangeJournal($origin),
                    $journalConfig,
                ),
            ),
            default => throw new RuntimeException(sprintf(
                'Unsupported storage config "%s".',
                $config::class,
            )),
        };
    }

    /**
     * The journal and storage share one lock, so a journal append re-enters the write it belongs to.
     */
    private function makeJsonStorage(
        Container $container,
        JsonStorageConfig $config,
        ?ChangeJournalConfig $journalConfig,
    ): JsonFileStorage {
        // Coroutines need a lock that yields rather than blocking the whole worker.
        $lock = $container->get(ServerOptions::class)->isRunnerMode(RunnerMode::Swoole)
            ? new CoroutineLock($config->path())
            : new FileLock($config->path());

        return new JsonFileStorage(
            $config->path(),
            $lock,
            $journalConfig === null ? null : AuditingChangeJournal::wrap(
                new FileChangeJournal(
                    $lock,
                    $config->path() . self::JOURNAL_SUFFIX,
                    $config->path() . self::SEQ_SUFFIX,
                    $this->journalOrigin($container),
                ),
                $journalConfig,
            ),
            $config->logger() ?? new NullLogger(),
        );
    }

    /**
     * The journal settings to build storage against, or null when nothing is recorded.
     */
    private function journalConfig(Container $container): ?ChangeJournalConfig
    {
        return $container->get(ServerOptions::class)
            ->getChangeJournalConfig();
    }

    /**
     * The identity stamped on changes this server authors.
     */
    private function journalOrigin(Container $container): ReplicaId
    {
        return $container->get(ServerOptions::class)
            ->getReplicationConfig()
            ->getId();
    }

    /**
     * The journal the storage was built with, or null when it has none.
     */
    private function changeJournal(Container $container): ?ChangeJournalInterface
    {
        $storage = $container->get(EntryStorageInterface::class);

        return $storage instanceof ChangeJournalingInterface
            ? $storage->changeJournal()
            : null;
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
            $options->getRunnerConfig()->getMode(),
            $this->journalOrigin($container),
            $container->get(SleeperInterface::class),
            $this->journalConfig($container),
        );
    }

    private function makeBackend(Container $container): WritableStorageBackend
    {
        $options = $container->get(ServerOptions::class);
        $storage = $container->get(EntryStorageInterface::class);

        return new WritableStorageBackend(
            storage: $storage,
            searchStream: $container->get(SearchStreamBuilder::class),
            validator: $this->buildSchemaValidator($container),
            listOptions: new StorageListOptionsFactory(
                $options->getSchema(),
                $options->makeSearchLimits(),
            ),
            filterEvaluator: $container->get(FilterEvaluatorInterface::class),
            operationalAttrs: $container->get(OperationalAttributeGenerator::class),
            changeRecorder: $this->changeRecorderFor($container, $storage),
        );
    }

    /**
     * Streams search results, post-filtering on the shared evaluator so matching rules follow the configured schema.
     */
    private function makeSearchStreamBuilder(Container $container): SearchStreamBuilder
    {
        $options = $container->get(ServerOptions::class);

        return new SearchStreamBuilder(
            $container->get(EntryStorageInterface::class),
            $options->makeSearchLimits(),
            $container->get(FilterEvaluatorInterface::class),
            $options->getSubschemaEntry(),
        );
    }

    /**
     * Bulk loading writes straight to storage, so it stamps and validates with the same components the write path uses.
     */
    private function makeLdapImporter(Container $container): LdapImporter
    {
        return new LdapImporter(
            $container->get(EntryStorageInterface::class),
            $container->get(OperationalAttributeGenerator::class),
            $this->buildSchemaValidator($container),
        );
    }

    /**
     * Schema-aware only when validation is on, so the generator stamps what the configured schema declares.
     */
    private function makeOperationalAttributeGenerator(Container $container): OperationalAttributeGenerator
    {
        $options = $container->get(ServerOptions::class);

        return new OperationalAttributeGenerator(
            $options->getSchemaValidationMode() !== SchemaValidationMode::Off
                ? $options->getSchema()
                : null,
        );
    }

    /**
     * The validator no-ops on its own when validation is Off, so one is always built.
     */
    private function buildSchemaValidator(Container $container): SchemaValidator
    {
        $options = $container->get(ServerOptions::class);

        return new SchemaValidator(
            $options->getSchema(),
            $options->getSchemaValidationMode(),
        );
    }

    /**
     * A recorder when sync is enabled and the storage was built with a journal to append to.
     */
    private function changeRecorderFor(
        Container $container,
        EntryStorageInterface $storage,
    ): ?ChangeRecorder {
        $options = $container->get(ServerOptions::class);

        if ($options->getChangeJournalConfig() === null || !$storage instanceof ChangeJournalingInterface) {
            return null;
        }

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
        return $container->get(ServerOptions::class)->isRunnerMode(RunnerMode::Swoole)
            ? new CoroutineSleeper()
            : new BlockingSleeper();
    }

    private function makeBackgroundTasks(Container $container): BackgroundTasksInterface
    {
        $options = $container->get(ServerOptions::class);
        $this->requirePdoStorageForReplica($options);

        return $options->isRunnerMode(RunnerMode::Swoole)
            ? $this->makeSwooleBackgroundTasks($container)
            : $this->makePcntlBackgroundTasks($container);
    }

    /**
     * Checked here rather than where the daemon is built, since the PCNTL runner only builds it after forking.
     *
     * @throws RuntimeException when a replica is configured without a database behind it
     */
    private function requirePdoStorageForReplica(ServerOptions $options): void
    {
        $storageConfig = $options->getStorageConfig();

        if ($options->getConsumerConfig() === null || $storageConfig instanceof PdoConfig) {
            return;
        }

        // The write-heavy apply path and the cross-process password-policy state both need a database.
        throw new RuntimeException(sprintf(
            'A read-only replica requires PDO storage, but "%s" is configured.',
            $storageConfig::class,
        ));
    }

    private function makeListenerContributor(Container $container): ListenerContributorInterface
    {
        $backend = $container->get(WritableStorageBackend::class);

        $instances = [
            WritableStorageBackend::class => $backend,
            EntryStorageInterface::class => $container->get(EntryStorageInterface::class),
        ];

        // On the PDO path, share the builder so the reloaded replica store stays on the storage's connection.
        if ($container->get(ServerOptions::class)->getStorageConfig() instanceof PdoConfig) {
            $instances[PdoBackendBuilder::class] = $container->get(PdoBackendBuilder::class);
        }

        return new DirectoryListenerContributor(
            $backend,
            $instances,
            $container->get(ServerOptions::class)->getStorageConfig()->type(),
        );
    }

    /**
     * The retention policy to sweep on, or null when journaling is off / has no limits.
     */
    private function journalRetentionPolicyIfSweepable(Container $container): ?RetentionPolicy
    {
        $options = $container->get(ServerOptions::class);

        if ($options->getChangeJournalConfig() === null) {
            return null;
        }

        $journal = $this->changeJournal($container);

        if ($journal === null) {
            return null;
        }

        $policy = $options->getChangeJournalConfig()->retention;

        return RetentionSweeper::isSweepable(
            $policy,
            $journal,
            $options->isRunnerMode(RunnerMode::Swoole),
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

        // Safe to resolve now: a non-null policy means sync is enabled and the storage was built with a journal.
        $journal = $this->changeJournal($container);

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
        if ($options->getConsumerConfig() !== null) {
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
        $config = $options->getConsumerConfig();

        if ($config === null) {
            return null;
        }

        return new PasswordPolicyForwardWorker(
            $container->get(ReplicaPasswordStateStoreInterface::class),
            new LdapClientForwardStateSender(new PrimaryConnectionFactory($config)),
            $container->get(SleeperInterface::class),
            interval: $config->getForwardInterval(),
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
        $config = $options->getConsumerConfig();

        if ($config === null) {
            return null;
        }

        $storage = $container->get(EntryStorageInterface::class);

        // Pair reconciliation with forwarding: the store drops forwarded state once the primary's entry replicates back.
        $passwordStateStore = $container->get(ReplicaPasswordStateStoreInterface::class);

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
