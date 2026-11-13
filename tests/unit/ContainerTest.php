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

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Config\ReplicationConfig;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\SubstringIndexMode;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\Decoder\ResponseMessageDecoder;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerFactoryMap;
use FreeDSx\Ldap\Protocol\Queue\Response\MetricsResponseInterceptor;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\ImmediateWriterQueue;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\SwooleWriterQueue;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriterQueueInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryLister;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryReader;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\SerializedEntryWriter;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\SerializingReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\NoSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\NonResettable;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedResolver;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Container\Contributor\ListenerContributorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use FreeDSx\Ldap\Server\Backend\Write\OperationalAttributeGenerator;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Recorder\MetricsRecorderChain;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Middleware\AssertionMiddleware;
use FreeDSx\Ldap\Server\Middleware\AttributeTypeCanonicalizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\CriticalControlMiddleware;
use FreeDSx\Ldap\Server\Middleware\MetricsMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuthorizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\ResourceLimitMiddleware;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\PasswordPolicyBindStrategyInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitResolver;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\ProxyServerOptions;
use FreeDSx\Ldap\Server\Proxy\ProxyProtocolFactory;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\PooledServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\ServerRunner as SwooleServerRunner;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use FreeDSx\Socket\SocketPool;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

use function str_repeat;

class ContainerTest extends TestCase
{
    use RequiresExtensionsTrait;

    private Container $subject;

    private string $memoryLimit = '';

    protected function setUp(): void
    {
        parent::setUp();

        $this->memoryLimit = (string) ini_get('memory_limit');
        $this->subject = Container::forServer(TestServerOptions::defaults());
    }

    protected function tearDown(): void
    {
        ini_set(
            'memory_limit',
            $this->memoryLimit,
        );

        parent::tearDown();
    }

    public function test_every_storage_contract_resolves_to_one_in_memory_store(): void
    {
        $container = Container::forServer(
            new ServerOptions(new InMemoryStorageConfig()),
        );
        $storage = $container->get(InMemoryStorage::class);

        self::assertSame(
            $storage,
            $container->get(ReadEntryInterface::class),
        );
        self::assertSame(
            $storage,
            $container->get(ListEntryInterface::class),
        );
        self::assertSame(
            $storage,
            $container->get(WriteEntryInterface::class),
        );
        self::assertSame(
            $storage,
            $container->get(TransactionalWriteInterface::class),
        );
    }

    public function test_a_pdo_config_reads_and_lists_in_place_but_writes_through_the_serializing_writer(): void
    {
        $container = Container::forServer(
            new ServerOptions(PdoConfig::forSqlite(':memory:')),
        );

        self::assertInstanceOf(
            EntryReader::class,
            $container->get(ReadEntryInterface::class),
        );
        self::assertInstanceOf(
            EntryLister::class,
            $container->get(ListEntryInterface::class),
        );
        self::assertInstanceOf(
            SerializedEntryWriter::class,
            $container->get(WriteEntryInterface::class),
        );
        self::assertSame(
            $container->get(WriteEntryInterface::class),
            $container->get(TransactionalWriteInterface::class),
        );
    }

    public function test_pdo_storage_writes_in_place_outside_the_swoole_runner(): void
    {
        $container = Container::forServer(
            new ServerOptions(PdoConfig::forSqlite(':memory:')),
        );

        self::assertInstanceOf(
            ImmediateWriterQueue::class,
            $container->get(WriterQueueInterface::class),
        );
    }

    public function test_pdo_storage_serializes_writes_under_the_swoole_runner_when_configured(): void
    {
        $this->requireSwoole();

        $path = tempnam(
            sys_get_temp_dir(),
            'container-',
        );
        self::assertIsString($path);
        $container = Container::forServer(
            (new ServerOptions(
                PdoConfig::forSqlite($path)
                    ->setSerializeSwooleWrites(true),
            ))->setRunnerConfig(new RunnerConfig(RunnerMode::Swoole)),
        );

        try {
            self::assertInstanceOf(
                SwooleWriterQueue::class,
                $container->get(WriterQueueInterface::class),
            );
        } finally {
            unlink($path);
        }
    }

    public function test_pdo_storage_writes_in_place_under_the_swoole_runner_when_not_serializing(): void
    {
        $container = Container::forServer(
            (new ServerOptions(
                PdoConfig::forSqlite('/tmp/unused.sqlite')
                    ->setSerializeSwooleWrites(false),
            ))->setRunnerConfig(new RunnerConfig(RunnerMode::Swoole)),
        );

        self::assertInstanceOf(
            ImmediateWriterQueue::class,
            $container->get(WriterQueueInterface::class),
        );
    }

    /**
     * @param class-string $class
     */
    #[DataProvider('sharedSingletonDataProvider')]
    public function test_it_shares_one_instance(string $class): void
    {
        self::assertSame(
            $this->subject->get($class),
            $this->subject->get($class),
        );
    }

    public function test_a_reload_keeps_the_change_journal_so_in_memory_records_survive(): void
    {
        $container = Container::forServer(
            (new ServerOptions(new InMemoryStorageConfig()))
                ->setChangeJournalConfig(new ChangeJournalConfig()),
        );

        self::assertSame(
            $container->get(ChangeJournalInterface::class),
            $container->get(ListenerContributorInterface::class)->reloadInstances()[ChangeJournalInterface::class] ?? null,
        );
    }

    public function test_a_reload_carries_no_change_journal_when_journaling_is_off(): void
    {
        $container = Container::forServer(new ServerOptions(new InMemoryStorageConfig()));

        self::assertArrayNotHasKey(
            ChangeJournalInterface::class,
            $container->get(ListenerContributorInterface::class)->reloadInstances(),
        );
    }

    public function test_a_fork_resets_the_pdo_connection_so_no_child_keeps_one_opened_before_it(): void
    {
        $container = Container::forServer(
            new ServerOptions(PdoConfig::forSqlite(':memory:')),
        );

        self::assertSame(
            $container->get(PdoConnection::class),
            $container->get(ListenerContributorInterface::class)->forkResettable(),
        );
    }

    public function test_a_fork_resets_nothing_for_in_memory_storage(): void
    {
        $container = Container::forServer(
            new ServerOptions(new InMemoryStorageConfig()),
        );

        self::assertInstanceOf(
            NonResettable::class,
            $container->get(ListenerContributorInterface::class)->forkResettable(),
        );
    }

    public function test_a_pdo_config_without_substring_indexing_resolves_the_null_index(): void
    {
        $container = Container::forServer(new ServerOptions(
            PdoConfig::forSqlite(':memory:')
                ->setSubstringIndexMode(SubstringIndexMode::None),
        ));

        self::assertInstanceOf(
            NoSubstringIndex::class,
            $container->get(SubstringIndexInterface::class),
        );
    }

    public function test_the_replica_password_store_is_pdo_backed_for_a_pdo_config(): void
    {
        $container = Container::forServer(
            new ServerOptions(PdoConfig::forSqlite(':memory:')),
        );

        self::assertInstanceOf(
            SerializingReplicaPasswordStateStore::class,
            $container->get(ReplicaPasswordStateStoreInterface::class),
        );
    }

    public function test_the_replica_password_store_is_refused_for_a_non_pdo_config(): void
    {
        $this->expectException(RuntimeException::class);

        $this->subject->get(ReplicaPasswordStateStoreInterface::class);
    }

    public function test_a_manager_password_under_an_unsupported_scheme_is_refused_naming_the_scheme(): void
    {
        $container = $this->containerFor(
            TestServerOptions::defaults()->setManager(new ManagerIdentity(
                new Dn('cn=manager'),
                '{PBKDF2-SHA512}10000$c2FsdA$aGFzaA',
            )),
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The manager password can never be verified. The "{PBKDF2-SHA512}" password scheme is not supported.');

        $container->get(ServerProtocolFactoryInterface::class);
    }

    public function test_a_cleartext_manager_password_over_the_length_limit_is_refused(): void
    {
        $container = $this->containerFor(
            TestServerOptions::defaults()->setManager(new ManagerIdentity(
                new Dn('cn=manager'),
                str_repeat(
                    'a',
                    513,
                ),
            )),
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('A cleartext password is longer than the configured hash limits allow.');

        $container->get(ServerProtocolFactoryInterface::class);
    }

    public function test_a_manager_password_under_a_supported_scheme_is_accepted(): void
    {
        $container = $this->containerFor(
            TestServerOptions::defaults()->setManager(new ManagerIdentity(
                new Dn('cn=manager'),
                '{SHA}aGFzaA==',
            )),
        );

        self::assertInstanceOf(
            ServerProtocolFactory::class,
            $container->get(ServerProtocolFactoryInterface::class),
        );
    }

    public function test_a_proxy_container_uses_the_proxy_protocol_factory(): void
    {
        $container = Container::forProxy(new ProxyOptions(new ProxyServerOptions()));

        self::assertInstanceOf(
            ProxyProtocolFactory::class,
            $container->get(ServerProtocolFactoryInterface::class),
        );
    }

    public function test_a_server_and_a_proxy_container_resolve_the_request_decoder(): void
    {
        self::assertInstanceOf(
            RequestMessageDecoder::class,
            $this->subject->get(RequestMessageDecoder::class),
        );
        self::assertInstanceOf(
            RequestMessageDecoder::class,
            Container::forProxy(new ProxyOptions(new ProxyServerOptions()))->get(RequestMessageDecoder::class),
        );
    }

    public function test_a_client_container_resolves_the_response_decoder(): void
    {
        self::assertInstanceOf(
            ResponseMessageDecoder::class,
            Container::forClient(new ClientOptions())->get(ResponseMessageDecoder::class),
        );
    }

    public function test_a_proxy_is_refused_when_it_requires_an_upstream_that_cannot_be_encrypted(): void
    {
        $container = Container::forProxy(new ProxyOptions(
            serverOptions: new ProxyServerOptions(),
            requireUpstreamConfidentiality: true,
        ));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The upstream connection is not encrypted.');

        $container->get(ServerProtocolFactoryInterface::class);
    }

    public function test_a_proxy_requiring_upstream_confidentiality_accepts_an_upstream_using_start_tls(): void
    {
        $container = Container::forProxy(new ProxyOptions(
            serverOptions: new ProxyServerOptions(),
            useStartTls: true,
            requireUpstreamConfidentiality: true,
        ));

        self::assertInstanceOf(
            ProxyProtocolFactory::class,
            $container->get(ServerProtocolFactoryInterface::class),
        );
    }

    public function test_a_proxy_requiring_upstream_confidentiality_accepts_an_upstream_using_ldaps(): void
    {
        $container = Container::forProxy(new ProxyOptions(
            serverOptions: new ProxyServerOptions(),
            clientOptions: (new ClientOptions())->setUseSsl(true),
            requireUpstreamConfidentiality: true,
        ));

        self::assertInstanceOf(
            ProxyProtocolFactory::class,
            $container->get(ServerProtocolFactoryInterface::class),
        );
    }

    /**
     * @return array<array{class-string}>
     */
    public static function clientDependenciesDataProvider(): array
    {
        return [
            [LdapClient::class],
            [ClientProtocolHandler::class],
            [ClientQueueInstantiator::class],
            [ClientProtocolHandlerFactory::class],
            [SocketPool::class],
            [RootDseLoader::class],
        ];
    }

    /**
     * Services a second consumer must not get its own copy of.
     *
     * @return array<array{class-string}>
     */
    public static function sharedSingletonDataProvider(): array
    {
        return [
            [ReadEntryInterface::class],
            [ListEntryInterface::class],
            [WriteEntryInterface::class],
            [TransactionalWriteInterface::class],
            [DerivedResolver::class],
            [SchemaValidator::class],
        ];
    }

    /**
     * @return array<array{class-string}>
     */
    public static function serverDependenciesDataProvider(): array
    {
        return [
            [ServerProtocolFactory::class],
            [BindNameResolverInterface::class],
            [PasswordAuthenticatableInterface::class],
            [ServerAuthorization::class],
            [SocketServerFactory::class],
            [MetricsRecorderInterface::class],
            [MetricsSnapshotProvider::class],
            [InMemoryMetricsRecorder::class],
            [SleeperInterface::class],
            [PasswordPolicyBindStrategyInterface::class],
            [PasswordPolicyResolver::class],
            [LdapImporter::class],
            [DerivedResolver::class],
            [SchemaValidator::class],
            [OperationalAttributeGenerator::class],
            [SearchLimitResolver::class],
            [AssertionEvaluator::class],
            [MetricsResponseInterceptor::class],
            [MetricsMiddleware::class],
            [CriticalControlMiddleware::class],
            [OperationAuthorizationMiddleware::class],
            [AssertionMiddleware::class],
            [AttributeTypeCanonicalizationMiddleware::class],
            [ResourceLimitMiddleware::class],
            [ProtocolHandlerFactoryMap::class],
        ];
    }

    public function test_the_sleeper_is_blocking_under_the_default_pcntl_runner(): void
    {
        self::assertInstanceOf(
            BlockingSleeper::class,
            $this->subject->get(SleeperInterface::class),
        );
    }

    /**
     * @param class-string $class
     */
    #[DataProvider('clientDependenciesDataProvider')]
    public function test_it_builds_the_client_dependencies(
        string $class,
    ): void {
        self::assertInstanceOf(
            $class,
            $this->clientContainer()->get($class),
        );
    }

    /**
     * @param class-string $class
     */
    #[DataProvider('serverDependenciesDataProvider')]
    public function test_it_builds_the_server_dependencies(
        string $class,
    ): void {
        self::assertInstanceOf(
            $class,
            $this->subject->get($class),
        );
    }

    public function test_it_should_make_the_default_ServerRunner(): void
    {
        $this->requirePcntl();
        $this->requirePosix();

        // Shared storage, since the forking runner refuses anything a fork would not carry.
        $container = $this->containerFor(TestServerOptions::forStorage($this->sharedStorage()));

        self::assertInstanceOf(
            ServerRunnerInterface::class,
            $container->get(ServerRunnerInterface::class),
        );
    }

    public function test_the_metrics_recorder_is_a_no_op_when_monitor_is_disabled(): void
    {
        self::assertInstanceOf(
            NullMetricsRecorder::class,
            $this->subject->get(MetricsRecorderInterface::class),
        );
    }

    public function test_the_metrics_recorder_is_in_memory_when_monitor_is_enabled(): void
    {
        $container = $this->containerFor((TestServerOptions::defaults())->setMonitorEnabled(true));

        self::assertInstanceOf(
            InMemoryMetricsRecorder::class,
            $container->get(MetricsRecorderInterface::class),
        );
    }

    public function test_the_metrics_recorder_chains_a_user_recorder_when_one_is_set(): void
    {
        $container = $this->containerFor(
            (TestServerOptions::defaults())
                ->setMonitorEnabled(true)
                ->setMetricsRecorder(new InMemoryMetricsRecorder()),
        );

        self::assertInstanceOf(
            MetricsRecorderChain::class,
            $container->get(MetricsRecorderInterface::class),
        );
    }

    public function test_the_snapshot_provider_is_the_live_recorder_under_swoole(): void
    {
        $this->requireSwoole();

        $container = $this->containerFor(
            (TestServerOptions::defaults())
                ->setMonitorEnabled(true)
                ->setRunnerConfig(new RunnerConfig(RunnerMode::Swoole)),
        );

        self::assertSame(
            $container->get(MetricsRecorderInterface::class),
            $container->get(MetricsSnapshotProvider::class),
        );
    }

    public function test_the_snapshot_provider_is_file_based_under_pcntl(): void
    {
        $container = $this->containerFor((TestServerOptions::defaults())->setMonitorEnabled(true));

        self::assertInstanceOf(
            FileSnapshotProvider::class,
            $container->get(MetricsSnapshotProvider::class),
        );
    }

    public function test_the_pcntl_runner_builds_with_journaling_and_retention_configured(): void
    {
        $this->requirePcntl();
        $this->requirePosix();

        $container = $this->containerFor($this->journalingOptions());

        self::assertInstanceOf(
            ServerRunnerInterface::class,
            $container->get(ServerRunnerInterface::class),
        );
    }

    public function test_the_swoole_runner_builds_with_a_retention_sweeper(): void
    {
        $this->requireSwoole();

        $container = $this->containerFor(
            $this->journalingOptions()->setRunnerConfig(new RunnerConfig(RunnerMode::Swoole)),
        );

        self::assertInstanceOf(
            ServerRunnerInterface::class,
            $container->get(ServerRunnerInterface::class),
        );
    }

    public function test_a_single_worker_builds_the_one_process_coroutine_runner(): void
    {
        $this->requireSwoole();

        $container = $this->containerFor(
            (TestServerOptions::defaults())->setRunnerConfig(new RunnerConfig(
                RunnerMode::Swoole,
                1,
            )),
        );

        self::assertInstanceOf(
            SwooleServerRunner::class,
            $container->get(ServerRunnerInterface::class),
        );
    }

    public function test_the_swoole_runner_is_refused_without_the_swoole_extension(): void
    {
        $this->requireMissingExtension('swoole');

        $container = $this->containerFor(
            (TestServerOptions::defaults())->setRunnerConfig(new RunnerConfig(RunnerMode::Swoole)),
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/Swoole extension/');

        $container->get(ServerRunnerInterface::class);
    }

    public function test_the_pcntl_runner_is_refused_without_process_control(): void
    {
        $this->requireMissingExtension(
            'pcntl',
            'posix',
        );

        $container = $this->containerFor(TestServerOptions::defaults());

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/pcntl and posix extensions/');

        $container->get(ServerRunnerInterface::class);
    }

    public function test_the_swoole_runner_is_refused_when_client_certificate_validation_is_on(): void
    {
        $this->requireSwoole();

        $container = $this->containerFor(
            (TestServerOptions::defaults())
                ->setRunnerConfig(new RunnerConfig(RunnerMode::Swoole))
                ->setNetworkConfig((new NetworkConfig())->setSslValidateCert(true)),
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The Swoole runner cannot verify client certificates.');

        $container->get(ServerRunnerInterface::class);
    }

    public function test_the_swoole_runner_is_refused_when_external_sasl_is_offered(): void
    {
        $this->requireSwoole();

        $container = $this->containerFor(
            (TestServerOptions::defaults())
                ->setRunnerConfig(new RunnerConfig(RunnerMode::Swoole))
                ->setSaslMechanisms(ServerOptions::SASL_EXTERNAL),
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The Swoole runner cannot support the EXTERNAL SASL mechanism.');

        $container->get(ServerRunnerInterface::class);
    }

    public function test_the_pcntl_runner_accepts_client_certificate_validation(): void
    {
        $this->requirePcntl();
        $this->requirePosix();

        $container = $this->containerFor(
            TestServerOptions::forStorage($this->sharedStorage())
                ->setNetworkConfig((new NetworkConfig())->setSslValidateCert(true))
                ->setSaslMechanisms(ServerOptions::SASL_EXTERNAL),
        );

        self::assertInstanceOf(
            PcntlServerRunner::class,
            $container->get(ServerRunnerInterface::class),
        );
    }

    public function test_several_workers_build_the_pooled_runner_for_shared_storage(): void
    {
        $this->requireSwoole();

        $container = $this->containerFor(
            (new ServerOptions(PdoConfig::forSqlite(sys_get_temp_dir() . '/freedsx_container_test.sqlite')))
                ->setRunnerConfig(new RunnerConfig(
                    RunnerMode::Swoole,
                    4,
                )),
        );

        self::assertInstanceOf(
            PooledServerRunner::class,
            $container->get(ServerRunnerInterface::class),
        );
    }

    public function test_several_workers_are_clamped_to_one_process_for_in_memory_storage(): void
    {
        $this->requireSwoole();
        ini_set(
            'memory_limit',
            '1G',
        );
        $logger = $this->createMock(LoggerInterface::class);
        $logger
            ->expects(self::once())
            ->method('log')
            ->with(
                LogLevel::WARNING,
                self::anything(),
                self::callback(static fn(array $context): bool => $context[EventContext::EVENT] === ServerEvent::ConcurrencyLimited->value
                    && $context[EventContext::REASON] === ConcurrencyLimitReason::StorageNotShareable->value
                    && $context['requested_workers'] === 4),
            );

        $container = $this->containerFor(
            (TestServerOptions::defaults())
                ->setLogger($logger)
                ->setRunnerConfig(new RunnerConfig(
                    RunnerMode::Swoole,
                    4,
                )),
        );

        self::assertInstanceOf(
            SwooleServerRunner::class,
            $container->get(ServerRunnerInterface::class),
        );
    }

    public function test_swoole_on_sqlite_warns_when_swoole_was_built_without_the_sqlite_hook(): void
    {
        $this->requireSwoole();
        if (defined('SWOOLE_HOOK_PDO_SQLITE')) {
            self::markTestSkipped('This Swoole build runs SQLite without blocking the worker.');
        }
        $logger = new RecordingLogger();

        $this->resolveSqliteConnection(
            RunnerConfig::forSwoole(1),
            $logger,
        );

        self::assertSame(
            [
                [
                    LogLevel::WARNING,
                    ConcurrencyLimitReason::StorageBlocksWorker->value,
                ],
            ],
            $this->concurrencyLimitsRecorded($logger),
        );
    }

    public function test_pcntl_on_sqlite_does_not_warn_about_blocking_the_worker(): void
    {
        $logger = new RecordingLogger();

        $this->resolveSqliteConnection(
            RunnerConfig::forPcntl(),
            $logger,
        );

        self::assertSame(
            [],
            $this->concurrencyLimitsRecorded($logger),
        );
    }

    public function test_a_held_request_size_too_small_for_the_largest_request_warns_at_startup(): void
    {
        $this->requirePcntl();
        $this->requirePosix();
        $logger = new RecordingLogger();
        $options = TestServerOptions::forStorage($this->sharedStorage())->setLogger($logger);
        $options->getNetworkConfig()->setMaxHeldRequestSize(1_000_000);

        $this->containerFor($options)->get(ServerRunnerInterface::class);

        self::assertSame(
            [
                [
                    LogLevel::WARNING,
                    ConcurrencyLimitReason::HeldRequestSize->value,
                ],
            ],
            $this->concurrencyLimitsRecorded($logger),
        );
    }

    public function test_a_held_request_size_too_small_for_the_elements_of_the_largest_request_warns_at_startup(): void
    {
        $this->requirePcntl();
        $this->requirePosix();
        $logger = new RecordingLogger();
        $options = TestServerOptions::forStorage($this->sharedStorage())->setLogger($logger);
        $options->getNetworkConfig()->setMaxHeldRequestSize(10_000_000);

        $this->containerFor($options)->get(ServerRunnerInterface::class);

        self::assertSame(
            [
                [
                    LogLevel::WARNING,
                    ConcurrencyLimitReason::HeldRequestSize->value,
                ],
            ],
            $this->concurrencyLimitsRecorded($logger),
        );
    }

    public function test_a_held_request_size_without_a_request_size_limit_warns_at_startup(): void
    {
        $this->requirePcntl();
        $this->requirePosix();
        $logger = new RecordingLogger();
        $options = TestServerOptions::forStorage($this->sharedStorage())->setLogger($logger);
        $options->getNetworkConfig()
            ->setMaxRequestSize(0)
            ->setMaxHeldRequestSize(10_000_000);

        $this->containerFor($options)->get(ServerRunnerInterface::class);

        self::assertSame(
            [
                [
                    LogLevel::WARNING,
                    ConcurrencyLimitReason::HeldRequestSize->value,
                ],
            ],
            $this->concurrencyLimitsRecorded($logger),
        );
    }

    public function test_the_default_held_request_size_does_not_warn_at_startup(): void
    {
        $this->requirePcntl();
        $this->requirePosix();
        ini_set(
            'memory_limit',
            '1G',
        );
        $logger = new RecordingLogger();

        $this->containerFor(
            TestServerOptions::forStorage($this->sharedStorage())->setLogger($logger),
        )->get(ServerRunnerInterface::class);

        self::assertSame(
            [],
            $this->concurrencyLimitsRecorded($logger),
        );
    }

    public function test_no_memory_limit_warns_at_startup_that_the_held_request_size_is_fixed(): void
    {
        $this->requirePcntl();
        $this->requirePosix();
        ini_set(
            'memory_limit',
            '-1',
        );
        $logger = new RecordingLogger();

        $this->containerFor(
            TestServerOptions::forStorage($this->sharedStorage())->setLogger($logger),
        )->get(ServerRunnerInterface::class);

        self::assertSame(
            [
                [
                    LogLevel::WARNING,
                    ConcurrencyLimitReason::NoMemoryLimit->value,
                ],
            ],
            $this->concurrencyLimitsRecorded($logger),
        );
    }

    public function test_swoole_warns_at_startup_when_its_connections_can_need_more_than_its_memory_limit(): void
    {
        $this->requireSwoole();
        ini_set(
            'memory_limit',
            '1G',
        );
        $logger = new RecordingLogger();
        $options = TestServerOptions::defaults()
            ->setLogger($logger)
            ->setRunnerConfig(new RunnerConfig(
                RunnerMode::Swoole,
                1,
            ));
        $options->getNetworkConfig()->setMaxConnections(50_000);

        $this->containerFor($options)->get(ServerRunnerInterface::class);

        self::assertContains(
            [
                LogLevel::WARNING,
                ConcurrencyLimitReason::MemoryLimit->value,
            ],
            $this->concurrencyLimitsRecorded($logger),
        );
    }

    public function test_swoole_without_a_held_request_size_limit_warns_at_startup_about_its_memory_limit(): void
    {
        $this->requireSwoole();
        ini_set(
            'memory_limit',
            '1G',
        );
        $logger = new RecordingLogger();
        $options = TestServerOptions::defaults()
            ->setLogger($logger)
            ->setRunnerConfig(new RunnerConfig(
                RunnerMode::Swoole,
                1,
            ));
        $options->getNetworkConfig()->setMaxHeldRequestSize(0);

        $this->containerFor($options)->get(ServerRunnerInterface::class);

        self::assertContains(
            [
                LogLevel::WARNING,
                ConcurrencyLimitReason::MemoryLimit->value,
            ],
            $this->concurrencyLimitsRecorded($logger),
        );
    }

    public function test_pcntl_does_not_warn_at_startup_about_its_connections_and_its_memory_limit(): void
    {
        $this->requirePcntl();
        $this->requirePosix();
        ini_set(
            'memory_limit',
            '1G',
        );
        $logger = new RecordingLogger();
        $options = TestServerOptions::forStorage($this->sharedStorage())->setLogger($logger);
        $options->getNetworkConfig()->setMaxConnections(50_000);

        $this->containerFor($options)->get(ServerRunnerInterface::class);

        self::assertSame(
            [],
            $this->concurrencyLimitsRecorded($logger),
        );
    }

    private function clientContainer(): Container
    {
        $client = new LdapClient();

        return Container::forClient(
            $client->getOptions(),
            $client,
        );
    }

    /**
     * A path rather than ':memory:', since a forking runner refuses storage a fork would not carry.
     */
    private function sharedStorage(): PdoConfig
    {
        return PdoConfig::forSqlite(sys_get_temp_dir() . '/freedsx_container_test.sqlite');
    }

    private function journalingOptions(): ServerOptions
    {
        return TestServerOptions::forStorage($this->sharedStorage())
            ->setReplicationConfig(ReplicationConfig::forProvider())
            ->setChangeJournalConfig(new ChangeJournalConfig(
                retention: new RetentionPolicy(maxRecords: 100),
            ));
    }

    private function containerFor(ServerOptions $options): Container
    {
        return Container::forServer($options);
    }

    private function resolveSqliteConnection(
        RunnerConfig $runnerConfig,
        RecordingLogger $logger,
    ): void {
        $path = tempnam(
            sys_get_temp_dir(),
            'container-',
        );
        self::assertIsString($path);

        try {
            $this->containerFor(
                (new ServerOptions(PdoConfig::forSqlite($path)))
                    ->setRunnerConfig($runnerConfig)
                    ->setLogger($logger),
            )->get(PdoConnectionProviderInterface::class);
        } finally {
            unlink($path);
        }
    }

    /**
     * @return list<array{string, mixed}>
     */
    private function concurrencyLimitsRecorded(RecordingLogger $logger): array
    {
        $recorded = [];

        foreach ($logger->records as $record) {
            if (($record['context'][EventContext::EVENT] ?? null) !== ServerEvent::ConcurrencyLimited->value) {
                continue;
            }
            $recorded[] = [
                $record['level'],
                $record['context'][EventContext::REASON] ?? null,
            ];
        }

        return $recorded;
    }
}
