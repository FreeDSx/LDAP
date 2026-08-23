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

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Exception\LdifParseException;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Ldif\Output\StringLdifOutput;
use FreeDSx\Ldap\Ldif\Url\FileUrlResolver;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DumpOptions;
use FreeDSx\Ldap\Server\Backend\Storage\SeedOptions;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Server\Config\Replication\ConsumerConfig;
use FreeDSx\Ldap\Server\Config\ReplicationConfig;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\TempFileUrlTrait;

class LdapServerTest extends TestCase
{
    use TempFileUrlTrait;

    private const SEED_LDIF = <<<'LDIF'
        dn: dc=example,dc=com
        objectClass: top
        objectClass: domain
        dc: example

        dn: cn=foo,dc=example,dc=com
        objectClass: top
        objectClass: person
        cn: foo
        sn: Bar
        LDIF;

    private const SUBTREE_LDIF = <<<'LDIF'
        dn: ou=people,dc=example,dc=com
        objectClass: top
        objectClass: organizationalUnit
        ou: people

        dn: cn=child,ou=people,dc=example,dc=com
        objectClass: top
        objectClass: person
        cn: child
        sn: Child
        LDIF;

    private LdapServer $subject;

    private ServerOptions $options;

    private Container $container;

    private ServerRunnerInterface&MockObject $mockServerRunner;

    protected function setUp(): void
    {
        $this->mockServerRunner = $this->createMock(ServerRunnerInterface::class);

        $this->options = (new ServerOptions(
            TestServerOptions::transientStorage(),
            networkConfig: NetworkConfig::withPort(33389),
        ))->setServerRunner($this->mockServerRunner);

        $this->container = Container::forServer($this->options);
        $this->subject = new LdapServer(
            $this->options,
            $this->container,
        );
    }

    public function test_it_should_run_the_server(): void
    {
        $this->mockServerRunner
            ->expects(self::once())
            ->method('run');

        $this->subject->run();
    }

    /**
     * Rejected while the runner is assembled, which is before it binds anything.
     */
    #[DataProvider('nonPdoReplicaStorageDataProvider')]
    public function test_building_the_runner_throws_for_a_replica_on_non_pdo_storage(
        StorageConfigInterface $storageConfig,
        RunnerMode $runner,
    ): void {
        if ($runner === RunnerMode::Swoole && !extension_loaded('swoole')) {
            self::markTestSkipped('The swoole extension is required to construct the Swoole runner.');
        }

        $options = (new ServerOptions(
            $storageConfig,
            networkConfig: NetworkConfig::withPort(33389),
        ))
            ->setReplicationConfig(ReplicationConfig::forReplica(new ConsumerConfig(new ClientOptions())))
            ->setRunnerConfig(new RunnerConfig($runner));

        $this->expectException(RuntimeException::class);

        Container::forServer($options)->get(ServerRunnerInterface::class);
    }

    public function test_run_does_not_throw_for_a_replica_on_pdo_storage(): void
    {
        $this->options
            ->setReplicationConfig(ReplicationConfig::forReplica(new ConsumerConfig(new ClientOptions())))
            ->setStorageConfig(PdoConfig::forSqlite(':memory:'));

        $this->mockServerRunner
            ->expects(self::once())
            ->method('run');

        $this->subject->run();
    }

    /**
     * Swoole shares one process, so storage that a fork would not carry is sound there.
     */
    public function test_run_does_not_throw_for_a_non_replica_on_unshared_storage_under_swoole(): void
    {
        $this->options
            ->setStorageConfig(InMemoryStorageConfig::withEntries())
            ->setRunnerConfig(new RunnerConfig(RunnerMode::Swoole));

        $this->mockServerRunner
            ->expects(self::once())
            ->method('run');

        $this->subject->run();
    }

    /**
     * A forking runner gives each connection its own copy, so a write would answer success and then be lost.
     */
    #[DataProvider('unsharedStorageDataProvider')]
    public function test_building_the_runner_throws_for_unshared_storage_under_a_forking_runner(
        StorageConfigInterface $storageConfig,
    ): void {
        $options = (new ServerOptions(
            $storageConfig,
            networkConfig: NetworkConfig::withPort(33389),
        ))->setRunnerConfig(new RunnerConfig(RunnerMode::Pcntl));

        $this->expectException(RuntimeException::class);

        Container::forServer($options)->get(ServerRunnerInterface::class);
    }

    /**
     * @return array<string, array{StorageConfigInterface, RunnerMode}>
     */
    public static function nonPdoReplicaStorageDataProvider(): array
    {
        return [
            'in-memory under pcntl' => [InMemoryStorageConfig::withEntries(), RunnerMode::Pcntl],
            'in-memory under swoole' => [InMemoryStorageConfig::withEntries(), RunnerMode::Swoole],
        ];
    }

    /**
     * @return array<string, array{StorageConfigInterface}>
     */
    public static function unsharedStorageDataProvider(): array
    {
        return [
            'in-memory' => [InMemoryStorageConfig::withEntries()],
            // Keyed on the config rather than the backend: an in-memory database belongs to one connection.
            'sqlite in-memory' => [PdoConfig::forSqlite(':memory:')],
        ];
    }

    public function test_it_does_not_throw_for_sasl_mechanisms_without_a_sasl_backend(): void
    {
        $this->mockServerRunner->method('run');

        $this->options->setSaslMechanisms(ServerOptions::SASL_PLAIN);

        $this->subject->run();

        $this->expectNotToPerformAssertions();
    }

    public function test_it_should_seed_entries_into_the_configured_storage(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        self::assertNotNull($this->storage()->find(new Dn('dc=example,dc=com')));
        $foo = $this->storage()->find(new Dn('cn=foo,dc=example,dc=com'));
        self::assertNotNull($foo);
        self::assertSame(
            ['Bar'],
            $foo->get('sn')?->getValues(),
        );
    }

    public function test_it_should_stamp_operational_attributes_on_seeded_entries(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $foo = $this->storage()->find(new Dn('cn=foo,dc=example,dc=com'));

        self::assertNotNull($foo);
        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $foo->get('entryUUID')?->getValues()[0] ?? '',
        );
        self::assertSame(
            'person',
            $foo->get('structuralObjectClass')?->getValues()[0],
        );
        self::assertSame(
            '',
            $foo->get('creatorsName')?->getValues()[0],
        );
    }

    public function test_it_should_record_the_creator_dn_when_seeding(): void
    {
        $this->subject->seed(
            new StringLdifLoader(self::SEED_LDIF),
            new SeedOptions(creatorDn: new Dn('cn=Importer,dc=example,dc=com')),
        );

        self::assertSame(
            'cn=Importer,dc=example,dc=com',
            $this->storage()->find(new Dn('cn=foo,dc=example,dc=com'))?->get('creatorsName')?->getValues()[0],
        );
    }

    public function test_it_should_seed_a_url_referenced_value_when_options_carry_a_resolver(): void
    {
        $url = $this->tempFileUrl('Bar');

        $this->subject->seed(
            new StringLdifLoader(
                "dn: dc=example,dc=com\nobjectClass: top\nobjectClass: domain\ndc: example\n"
                . "\n"
                . "dn: cn=foo,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: foo\nsn:< $url\n",
            ),
            new SeedOptions(urlResolver: new FileUrlResolver()),
        );

        self::assertSame(
            ['Bar'],
            $this->storage()->find(new Dn('cn=foo,dc=example,dc=com'))?->get('sn')?->getValues(),
        );
    }

    public function test_it_should_refuse_a_url_referenced_value_when_seeding_without_a_resolver(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('URL-referenced');

        $this->subject->seed(new StringLdifLoader(
            "dn: cn=foo,dc=example,dc=com\nobjectClass: person\ncn: foo\nsn:< file:///tmp/x\n",
        ));
    }

    public function test_it_should_reject_seeding_when_the_ldif_contains_change_records(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('only accepts content records');

        $this->subject->seed(new StringLdifLoader("dn: cn=any,dc=x\nchangetype: delete\n"));
    }

    public function test_it_should_apply_modify_changes_against_the_seeded_storage(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $this->subject->applyChanges(new StringLdifLoader(
            "dn: cn=foo,dc=example,dc=com\nchangetype: modify\nreplace: sn\nsn: Updated\n-\n",
        ));

        self::assertSame(
            ['Updated'],
            $this->storage()->find(new Dn('cn=foo,dc=example,dc=com'))?->get('sn')?->getValues(),
        );
    }

    public function test_it_should_apply_a_delete_change_against_the_seeded_storage(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $this->subject->applyChanges(new StringLdifLoader(
            "dn: cn=foo,dc=example,dc=com\nchangetype: delete\n",
        ));

        self::assertNull($this->storage()->find(new Dn('cn=foo,dc=example,dc=com')));
    }

    /**
     * RFC 2849 lets a change record carry controls, and the wire path routes this one to a subtree delete.
     */
    public function test_it_should_apply_a_delete_carrying_the_subtree_control_to_the_whole_subtree(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF . "\n\n" . self::SUBTREE_LDIF));

        $this->subject->applyChanges(new StringLdifLoader(
            "dn: ou=people,dc=example,dc=com\ncontrol: 1.2.840.113556.1.4.805 true\nchangetype: delete\n",
        ));

        self::assertNull($this->storage()->find(new Dn('cn=child,ou=people,dc=example,dc=com')));
        self::assertNull($this->storage()->find(new Dn('ou=people,dc=example,dc=com')));
    }

    public function test_it_should_refuse_a_change_record_carrying_a_critical_control_it_cannot_honor(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNAVAILABLE_CRITICAL_EXTENSION);

        $this->subject->applyChanges(new StringLdifLoader(
            "dn: cn=foo,dc=example,dc=com\ncontrol: 1.3.6.1.1.13.1 true\nchangetype: delete\n",
        ));
    }

    public function test_it_should_apply_a_change_record_carrying_a_non_critical_control_it_cannot_honor(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $this->subject->applyChanges(new StringLdifLoader(
            "dn: cn=foo,dc=example,dc=com\ncontrol: 1.3.6.1.1.13.1 false\nchangetype: delete\n",
        ));

        self::assertNull($this->storage()->find(new Dn('cn=foo,dc=example,dc=com')));
    }

    public function test_it_should_refuse_to_seed_a_read_only_replica(): void
    {
        $options = (new ServerOptions(
            PdoConfig::forSqlite(':memory:'),
            networkConfig: NetworkConfig::withPort(33389),
        ))->setReplicationConfig(ReplicationConfig::forReplica(new ConsumerConfig(new ClientOptions())));

        $this->expectException(RuntimeException::class);

        (new LdapServer($options, Container::forServer($options)))
            ->seed(new StringLdifLoader(self::SEED_LDIF));
    }

    public function test_it_should_dump_seeded_entries_to_the_given_output(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $output = new StringLdifOutput();
        $this->subject->dump(
            $output,
            (new DumpOptions())->setBaseDn(new Dn('dc=example,dc=com')),
        );

        $ldif = $output->getLdif();
        self::assertStringStartsWith(
            'version: 1',
            $ldif,
        );
        self::assertStringContainsString(
            'dn: dc=example,dc=com',
            $ldif,
        );
        self::assertStringContainsString(
            'dn: cn=foo,dc=example,dc=com',
            $ldif,
        );
    }

    public function test_dump_seed_round_trip_preserves_entryUUID_and_create_timestamp(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $originalFoo = $this->storage()->find(new Dn('cn=foo,dc=example,dc=com'));
        self::assertNotNull($originalFoo);
        $originalUuid = $originalFoo->get('entryUUID')?->firstValue();
        $originalTimestamp = $originalFoo->get('createTimestamp')?->firstValue();
        self::assertNotNull($originalUuid);
        self::assertNotNull($originalTimestamp);

        $output = new StringLdifOutput();
        $this->subject->dump(
            $output,
            (new DumpOptions())->setBaseDn(new Dn('dc=example,dc=com')),
        );

        $restoreOptions = TestServerOptions::defaults();
        $restoreContainer = Container::forServer($restoreOptions);
        (new LdapServer(
            $restoreOptions,
            $restoreContainer,
        ))->seed(new StringLdifLoader($output->getLdif()));

        $restoredFoo = $restoreContainer->get(EntryStorageInterface::class)
            ->find(new Dn('cn=foo,dc=example,dc=com'));
        self::assertNotNull($restoredFoo);
        self::assertSame(
            $originalUuid,
            $restoredFoo->get('entryUUID')?->firstValue(),
        );
        self::assertSame(
            $originalTimestamp,
            $restoredFoo->get('createTimestamp')?->firstValue(),
        );
    }

    public function test_it_should_apply_the_dump_options_filter(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $output = new StringLdifOutput();
        $this->subject->dump(
            $output,
            (new DumpOptions())
                ->setBaseDn(new Dn('dc=example,dc=com'))
                ->setFilter(Filters::equal('objectClass', 'person')),
        );

        self::assertStringContainsString(
            'cn=foo,dc=example,dc=com',
            $output->getLdif(),
        );
        self::assertStringNotContainsString(
            'dn: dc=example,dc=com',
            $output->getLdif(),
        );
    }

    /**
     * The container-built storage the server operates on.
     */
    private function storage(): EntryStorageInterface
    {
        return $this->container->get(EntryStorageInterface::class);
    }
}
