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

use FreeDSx\Ldap\Server\Config\ReplicationConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerFactoryMap;
use FreeDSx\Ldap\Protocol\Queue\Response\MetricsResponseInterceptor;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedResolver;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use FreeDSx\Ldap\Server\Backend\Storage\OperationalAttributeGenerator;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Recorder\MetricsRecorderChain;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Middleware\AssertionMiddleware;
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
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\PooledServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\ServerRunner as SwooleServerRunner;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use FreeDSx\Socket\SocketPool;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ContainerTest extends TestCase
{
    private Container $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->subject = Container::forServer(TestServerOptions::defaults());
    }

    public function test_it_builds_in_memory_storage_from_an_in_memory_config(): void
    {
        $container = Container::forServer(
            new ServerOptions(InMemoryStorageConfig::withEntries()),
        );

        self::assertInstanceOf(
            InMemoryStorage::class,
            $container->get(EntryStorageInterface::class),
        );
    }

    public function test_it_builds_a_pdo_backend_from_a_pdo_config(): void
    {
        $container = Container::forServer(
            new ServerOptions(PdoConfig::forSqlite(':memory:')),
        );

        self::assertInstanceOf(
            PdoStorage::class,
            $container->get(EntryStorageInterface::class),
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

    public function test_the_replica_password_store_is_pdo_backed_for_a_pdo_config(): void
    {
        $container = Container::forServer(
            new ServerOptions(PdoConfig::forSqlite(':memory:')),
        );

        self::assertInstanceOf(
            PdoReplicaPasswordStateStore::class,
            $container->get(ReplicaPasswordStateStoreInterface::class),
        );
    }

    public function test_the_replica_password_store_is_refused_for_a_non_pdo_config(): void
    {
        $this->expectException(RuntimeException::class);

        $this->subject->get(ReplicaPasswordStateStoreInterface::class);
    }

    public function test_a_proxy_container_uses_the_proxy_protocol_factory(): void
    {
        $container = Container::forProxy(new ProxyOptions(new ProxyServerOptions()));

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
            [EntryStorageInterface::class],
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
        if (str_starts_with(strtoupper(PHP_OS), 'WIN')) {
            self::markTestSkipped('Cannot construct the default PCNTL runner on Windows.');
        }

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
        if (!extension_loaded('swoole')) {
            self::markTestSkipped('The swoole extension is required to construct the shared metrics table.');
        }

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
        if (str_starts_with(strtoupper(PHP_OS), 'WIN')) {
            self::markTestSkipped('Cannot construct the default PCNTL runner on Windows.');
        }

        $container = $this->containerFor($this->journalingOptions());

        self::assertInstanceOf(
            ServerRunnerInterface::class,
            $container->get(ServerRunnerInterface::class),
        );
    }

    public function test_the_swoole_runner_builds_with_a_retention_sweeper(): void
    {
        if (!extension_loaded('swoole')) {
            self::markTestSkipped('The swoole extension is required to construct the Swoole runner.');
        }

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
        if (!extension_loaded('swoole')) {
            self::markTestSkipped('The swoole extension is required.');
        }

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

    /**
     * Each worker would open its own database, so the backend is shared in name only.
     */
    public function test_several_workers_are_clamped_to_one_process_for_an_in_memory_database(): void
    {
        if (!extension_loaded('swoole')) {
            self::markTestSkipped('The swoole extension is required.');
        }

        $container = $this->containerFor(
            (new ServerOptions(PdoConfig::forSqlite(':memory:')))
                ->setRunnerConfig(new RunnerConfig(
                    RunnerMode::Swoole,
                    4,
                )),
        );

        self::assertNotInstanceOf(
            PooledServerRunner::class,
            $container->get(ServerRunnerInterface::class),
        );
    }

    public function test_several_workers_build_the_pooled_runner_for_shared_storage(): void
    {
        if (!extension_loaded('swoole')) {
            self::markTestSkipped('The swoole extension is required.');
        }

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
        if (!extension_loaded('swoole')) {
            self::markTestSkipped('The swoole extension is required.');
        }

        $container = $this->containerFor(
            (TestServerOptions::defaults())->setRunnerConfig(new RunnerConfig(
                RunnerMode::Swoole,
                4,
            )),
        );

        self::assertInstanceOf(
            SwooleServerRunner::class,
            $container->get(ServerRunnerInterface::class),
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
}
