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
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\ConfidentialAttributeAccessControl;
use FreeDSx\Ldap\Server\AccessControl\ConfidentialAttributePolicy;
use FreeDSx\Ldap\Server\AccessControl\PrivilegedBypassAccessControl;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoBackend;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedResolver;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DirectoryDumper;
use FreeDSx\Ldap\Server\Backend\Write\Replay\WriteRequestReplayer;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluator;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Write\AtomicWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\EntryLocator;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\SubtreeEnumerator;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\SubtreeMoveRecorder;
use FreeDSx\Ldap\Server\Backend\Write\Operation\AddEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\ComputeUpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteSubtreeCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Operation\ComputeUpdateHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\DeleteEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\DeleteSubtreeHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\EntryMutation;
use FreeDSx\Ldap\Server\Backend\Write\Operation\EntryPlacementGuard;
use FreeDSx\Ldap\Server\Backend\Write\Operation\MoveEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\UpdateEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolationGate;
use FreeDSx\Ldap\Server\Subentry\SubentryPlacementGuard;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionSweeper;
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\WriteEntryOperationHandler;
use FreeDSx\Ldap\Server\Backend\Write\OperationalAttributeGenerator;
use FreeDSx\Ldap\Server\Backend\Storage\Search\SearchStreamBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\Search\StorageListOptionsFactory;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\StorageReadBackend;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\CoroutineSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Clock\SystemClock;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\ConnectionHandlerBuilderInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\AttributeSearchBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverChain;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\DnBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticator;
use FreeDSx\Ldap\Server\Backend\Write\Replay\ReplayWriteHandler;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Backend\Write\Routing\WriteRequestRouter;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Middleware\AssertionMiddleware;
use FreeDSx\Ldap\Server\Middleware\CriticalControlMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuditMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareChain;
use FreeDSx\Ldap\Server\Middleware\ReadOnlyMiddleware;
use FreeDSx\Ldap\Server\Middleware\RequestValidationMiddleware;
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
use FreeDSx\Ldap\Ldif\LdifParser;
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
            AccessControlInterface::class => $this->makeAccessControl(...),
            BindNameResolverInterface::class => $this->makeIdentityResolverChain(...),
            PasswordAuthenticatableInterface::class => $this->makePasswordAuthenticator(...),
            FilterEvaluatorInterface::class => $this->makeFilterEvaluator(...),
            DerivedResolver::class => $this->makeDerivedResolver(...),
            SchemaValidator::class => $this->buildSchemaValidator(...),
            EqualityComparatorResolver::class => $this->makeEqualityComparatorResolver(...),
            DirectoryDumper::class => $this->makeDirectoryDumper(...),
            OperationalAttributeGenerator::class => $this->makeOperationalAttributeGenerator(...),
            SearchStreamBuilder::class => $this->makeSearchStreamBuilder(...),
            LdapImporter::class => $this->makeLdapImporter(...),
            LdifParser::class => static fn(): LdifParser => new LdifParser(),
            EntryLocator::class => static fn(Container $c): EntryLocator => new EntryLocator(
                $c->get(EntryStorageInterface::class),
            ),
            SubtreeEnumerator::class => static fn(Container $c): SubtreeEnumerator => new SubtreeEnumerator(
                $c->get(EntryStorageInterface::class),
            ),
            AtomicWriter::class => static fn(Container $c): AtomicWriter => new AtomicWriter(
                $c->get(EntryStorageInterface::class),
            ),
            SubentryPlacementGuard::class => static fn(Container $c): SubentryPlacementGuard => new SubentryPlacementGuard(
                $c->get(EntryStorageInterface::class),
            ),
            SchemaViolationGate::class => static fn(Container $c): SchemaViolationGate => new SchemaViolationGate(
                $c->get(SchemaValidator::class),
            ),
            WriteEntryOperationHandler::class => static fn(Container $c): WriteEntryOperationHandler => new WriteEntryOperationHandler(
                $c->get(EqualityComparatorResolver::class),
            ),
            EntryPlacementGuard::class => static fn(Container $c): EntryPlacementGuard => new EntryPlacementGuard(
                $c->get(EntryStorageInterface::class),
                $c->get(EntryLocator::class),
                $c->get(SubentryPlacementGuard::class),
            ),
            EntryMutation::class => static fn(Container $c): EntryMutation => new EntryMutation(
                $c->get(WriteEntryOperationHandler::class),
                $c->get(SchemaViolationGate::class),
                $c->get(OperationalAttributeGenerator::class),
            ),
            AddEntryHandler::class => $this->makeAddEntryHandler(...),
            DeleteEntryHandler::class => $this->makeDeleteEntryHandler(...),
            DeleteSubtreeHandler::class => $this->makeDeleteSubtreeHandler(...),
            UpdateEntryHandler::class => $this->makeUpdateEntryHandler(...),
            ComputeUpdateHandler::class => $this->makeComputeUpdateHandler(...),
            MoveEntryHandler::class => $this->makeMoveEntryHandler(...),
            WriteOperationDispatcher::class => static fn(Container $c): WriteOperationDispatcher => new WriteOperationDispatcher([
                AddCommand::class => $c->get(AddEntryHandler::class)->handle(...),
                DeleteCommand::class => $c->get(DeleteEntryHandler::class)->handle(...),
                DeleteSubtreeCommand::class => $c->get(DeleteSubtreeHandler::class)->handle(...),
                UpdateCommand::class => $c->get(UpdateEntryHandler::class)->handle(...),
                ComputeUpdateCommand::class => $c->get(ComputeUpdateHandler::class)->handle(...),
                MoveCommand::class => $c->get(MoveEntryHandler::class)->handle(...),
            ]),
            StorageReadBackend::class => $this->makeBackend(...),
            ReadBackendInterface::class => static fn(Container $c): ReadBackendInterface => $c->get(StorageReadBackend::class),
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
        $acl->setBackend($container->get(ReadBackendInterface::class));

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
                $container->get(ReadBackendInterface::class),
            );
    }

    private function makeFilterEvaluator(Container $container): FilterEvaluator
    {
        return new FilterEvaluator(
            $container->get(ServerOptions::class)->getSchema(),
            $container->get(DerivedResolver::class),
            $container->get(EqualityComparatorResolver::class),
            $this->makeAttributeSyntaxResolver($container),
        );
    }

    private function makeAttributeSyntaxResolver(Container $container): AttributeSyntaxResolver
    {
        return new AttributeSyntaxResolver(
            $container->get(ServerOptions::class)->getSchema(),
        );
    }

    private function makeEqualityComparatorResolver(Container $container): EqualityComparatorResolver
    {
        return new EqualityComparatorResolver(
            $container->get(ServerOptions::class)->getSchema(),
        );
    }

    private function makeDerivedResolver(Container $container): DerivedResolver
    {
        return new DerivedResolver(
            $container->get(EntryStorageInterface::class),
            $container->get(ServerOptions::class)->getSubschemaEntry(),
        );
    }

    /**
     * Replay runs the pipeline stages that need no connection, so it cannot drift from the wire path.
     */
    private function makeWriteRequestReplayer(Container $container): WriteRequestReplayer
    {
        $options = $container->get(ServerOptions::class);
        $consumerConfig = $options->getConsumerConfig();

        return new WriteRequestReplayer(new MiddlewareChain(
            [
                new RequestValidationMiddleware(),
                new OperationAuditMiddleware(new OperationAuditor(new EventLogger(
                    $options->getLogger(),
                    $options->getEventLogPolicy(),
                    (new ConnectionContext())->toLogContext(),
                ))),
                ...($consumerConfig !== null
                    ? [new ReadOnlyMiddleware($consumerConfig)]
                    : []),
                $container->get(CriticalControlMiddleware::class),
                $container->get(AssertionMiddleware::class),
            ],
            new ReplayWriteHandler(new WriteRequestRouter(
                $container->get(WriteOperationDispatcher::class),
            )),
        ));
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
     * The journal the storage was built with, or null when it has none.
     */
    private function changeJournal(Container $container): ?ChangeJournalInterface
    {
        $storage = $container->get(EntryStorageInterface::class);

        return $storage instanceof ChangeJournalingInterface
            ? $storage->changeJournal()
            : null;
    }

    private function makeBackend(Container $container): StorageReadBackend
    {
        return new StorageReadBackend(
            storage: $container->get(EntryStorageInterface::class),
            searchStream: $container->get(SearchStreamBuilder::class),
            listOptions: $container->get(StorageListOptionsFactory::class),
            filterEvaluator: $container->get(FilterEvaluatorInterface::class),
            locator: $container->get(EntryLocator::class),
        );
    }

    private function makeAddEntryHandler(Container $container): AddEntryHandler
    {
        return new AddEntryHandler(
            storage: $container->get(EntryStorageInterface::class),
            writer: $container->get(AtomicWriter::class),
            placement: $container->get(EntryPlacementGuard::class),
            schemaGate: $container->get(SchemaViolationGate::class),
            operationalAttrs: $container->get(OperationalAttributeGenerator::class),
            changeRecorder: $this->changeRecorderFor($container),
        );
    }

    private function makeDeleteEntryHandler(Container $container): DeleteEntryHandler
    {
        return new DeleteEntryHandler(
            storage: $container->get(EntryStorageInterface::class),
            writer: $container->get(AtomicWriter::class),
            locator: $container->get(EntryLocator::class),
            placement: $container->get(EntryPlacementGuard::class),
            changeRecorder: $this->changeRecorderFor($container),
        );
    }

    private function makeDeleteSubtreeHandler(Container $container): DeleteSubtreeHandler
    {
        return new DeleteSubtreeHandler(
            storage: $container->get(EntryStorageInterface::class),
            writer: $container->get(AtomicWriter::class),
            locator: $container->get(EntryLocator::class),
            placement: $container->get(EntryPlacementGuard::class),
            subtree: $container->get(SubtreeEnumerator::class),
            accessControl: $container->get(AccessControlInterface::class),
            changeRecorder: $this->changeRecorderFor($container),
        );
    }

    private function makeUpdateEntryHandler(Container $container): UpdateEntryHandler
    {
        return new UpdateEntryHandler(
            storage: $container->get(EntryStorageInterface::class),
            writer: $container->get(AtomicWriter::class),
            locator: $container->get(EntryLocator::class),
            mutation: $container->get(EntryMutation::class),
            placement: $container->get(EntryPlacementGuard::class),
            changeRecorder: $this->changeRecorderFor($container),
        );
    }

    private function makeComputeUpdateHandler(Container $container): ComputeUpdateHandler
    {
        return new ComputeUpdateHandler(
            storage: $container->get(EntryStorageInterface::class),
            writer: $container->get(AtomicWriter::class),
            locator: $container->get(EntryLocator::class),
            mutation: $container->get(EntryMutation::class),
            placement: $container->get(EntryPlacementGuard::class),
            changeRecorder: $this->changeRecorderFor($container),
        );
    }

    private function makeMoveEntryHandler(Container $container): MoveEntryHandler
    {
        $recorder = $this->changeRecorderFor($container);

        return new MoveEntryHandler(
            storage: $container->get(EntryStorageInterface::class),
            writer: $container->get(AtomicWriter::class),
            locator: $container->get(EntryLocator::class),
            mutation: $container->get(EntryMutation::class),
            placement: $container->get(EntryPlacementGuard::class),
            moveRecorder: $recorder === null
                ? null
                : new SubtreeMoveRecorder(
                    $recorder,
                    $container->get(SubtreeEnumerator::class),
                ),
        );
    }

    /**
     * Streams search results, post-filtering on the shared evaluator so matching rules follow the configured schema.
     */
    private function makeSearchStreamBuilder(Container $container): SearchStreamBuilder
    {
        $options = $container->get(ServerOptions::class);

        return new SearchStreamBuilder(
            $options->makeSearchLimits(),
            $container->get(FilterEvaluatorInterface::class),
            $container->get(DerivedResolver::class),
        );
    }

    /**
     * Bulk loading writes straight to storage, so it stamps and validates with the same components the write path uses.
     */
    private function makeLdapImporter(Container $container): LdapImporter
    {
        $this->refuseBulkImportOnReplica($container->get(ServerOptions::class));

        return new LdapImporter(
            $container->get(EntryStorageInterface::class),
            $container->get(OperationalAttributeGenerator::class),
            $container->get(SchemaValidator::class),
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
    private function changeRecorderFor(Container $container): ?ChangeRecorder
    {
        $options = $container->get(ServerOptions::class);
        $storage = $container->get(EntryStorageInterface::class);

        if ($options->getChangeJournalConfig() === null || !$storage instanceof ChangeJournalingInterface) {
            return null;
        }

        return new ChangeRecorder(
            $storage,
            $options->getLogger() ?? new NullLogger(),
        );
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
        $this->requireSharedStorageWhenForking($options);

        return $options->isRunnerMode(RunnerMode::Swoole)
            ? $this->makeSwooleBackgroundTasks($container)
            : $this->makePcntlBackgroundTasks($container);
    }

    /**
     * The PCNTL runner forks per connection, so storage only that process can see makes a write vanish with the
     * connection that made it while still answering success. Swoole is exempt, since its workers share memory.
     *
     * @throws RuntimeException when a forking runner is paired with storage it cannot share
     */
    private function requireSharedStorageWhenForking(ServerOptions $options): void
    {
        $storageConfig = $options->getStorageConfig();

        if ($options->isRunnerMode(RunnerMode::Swoole) || $storageConfig->isMultiProcessSafe()) {
            return;
        }

        throw new RuntimeException(sprintf(
            'The %s runner forks per connection, so "%s" is not safe to use. See the docs for more details.',
            RunnerMode::Pcntl->name,
            $storageConfig::class,
        ));
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

    /**
     * @throws RuntimeException when a replica would be seeded locally
     */
    private function refuseBulkImportOnReplica(ServerOptions $options): void
    {
        if (!$options->isReadOnly()) {
            return;
        }

        // The provider owns a replica's content, so the next refresh would sweep away whatever was imported here.
        throw new RuntimeException('A read-only replica cannot be seeded locally; seed the provider instead.');
    }

    private function makeListenerContributor(Container $container): ListenerContributorInterface
    {
        // The concrete key, since the reloaded generation resolves its interface alias through this instance.
        $backend = $container->get(StorageReadBackend::class);

        $instances = [
            StorageReadBackend::class => $backend,
            EntryStorageInterface::class => $container->get(EntryStorageInterface::class),
        ];

        // On the PDO path, share the builder so the reloaded replica store stays on the storage's connection.
        if ($container->get(ServerOptions::class)->getStorageConfig() instanceof PdoConfig) {
            $instances[PdoBackend::class] = $container->get(PdoBackend::class);
        }

        return new DirectoryListenerContributor(
            $backend,
            $instances,
            $container->get(ServerOptions::class)->getStorageConfig(),
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
