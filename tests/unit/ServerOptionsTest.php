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

use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\Nis\AttributeTypeOid as NisAttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\Config\PasswordConfig;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\Replication\ConsumerConfig;
use FreeDSx\Ldap\Server\Config\ReplicationConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\ExternalCredentialMapperInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitRule;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitRules;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

final class ServerOptionsTest extends TestCase
{
    private ServerOptions $subject;

    protected function setUp(): void
    {
        $this->subject = TestServerOptions::defaults();
    }

    public function test_a_default_server_plays_no_replication_role(): void
    {
        self::assertFalse($this->subject->isReadOnly());
        self::assertNull($this->subject->getConsumerConfig());
        self::assertFalse($this->subject->getReplicationConfig()->isProvider());
        self::assertFalse($this->subject->getReplicationConfig()->isConsumer());
    }

    public function test_a_consumer_role_makes_the_server_read_only(): void
    {
        $config = new ConsumerConfig(new ClientOptions());
        $options = new ServerOptions(
            storageConfig: PdoConfig::forSqlite(':memory:'),
            replicationConfig: ReplicationConfig::forReplica($config),
        );

        self::assertTrue($options->isReadOnly());
        self::assertSame(
            $config,
            $options->getConsumerConfig(),
        );
    }

    public function test_sasl_mechanisms_are_empty_by_default(): void
    {
        self::assertSame(
            [],
            $this->subject->getSaslMechanisms(),
        );
    }

    public function test_it_can_set_supported_sasl_mechanisms(): void
    {
        $this->subject->setSaslMechanisms(
            ServerOptions::SASL_PLAIN,
            ServerOptions::SASL_CRAM_MD5,
        );

        self::assertSame(
            [ServerOptions::SASL_PLAIN, ServerOptions::SASL_CRAM_MD5],
            $this->subject->getSaslMechanisms(),
        );
    }

    public function test_it_can_set_the_external_sasl_mechanism(): void
    {
        $this->subject->setSaslMechanisms(ServerOptions::SASL_EXTERNAL);

        self::assertSame(
            [ServerOptions::SASL_EXTERNAL],
            $this->subject->getSaslMechanisms(),
        );
    }

    public function test_external_credential_mapper_is_null_by_default(): void
    {
        self::assertNull($this->subject->getExternalCredentialMapper());
    }

    public function test_it_can_set_an_external_credential_mapper(): void
    {
        $mapper = $this->createMock(ExternalCredentialMapperInterface::class);

        $this->subject->setExternalCredentialMapper($mapper);

        self::assertSame(
            $mapper,
            $this->subject->getExternalCredentialMapper(),
        );
    }

    public function test_it_throws_for_an_unsupported_sasl_mechanism(): void
    {
        self::expectException(InvalidArgumentException::class);

        $this->subject->setSaslMechanisms('GSSAPI');
    }

    public function test_it_throws_for_any_unsupported_mechanism_in_the_list(): void
    {
        self::expectException(InvalidArgumentException::class);

        $this->subject->setSaslMechanisms(ServerOptions::SASL_PLAIN, 'GSSAPI');
    }

    public function test_monitor_is_disabled_by_default(): void
    {
        self::assertFalse($this->subject->isMonitorEnabled());
    }

    public function test_it_can_enable_the_monitor(): void
    {
        $this->subject->setMonitorEnabled(true);

        self::assertTrue($this->subject->isMonitorEnabled());
    }

    public function test_monitor_snapshot_path_defaults_to_a_per_port_temp_file(): void
    {
        self::assertSame(
            sys_get_temp_dir() . '/freedsx_ldap_monitor_389.json',
            $this->subject->getMonitorSnapshotPath(),
        );
    }

    public function test_a_provider_role_journals_without_the_journal_being_configured(): void
    {
        $this->subject->setReplicationConfig(ReplicationConfig::forProvider());

        self::assertNotNull($this->subject->getChangeJournalConfig());
    }

    public function test_nothing_is_journaled_by_default(): void
    {
        self::assertNull($this->subject->getChangeJournalConfig());
    }

    public function test_a_journal_can_be_configured_without_a_replication_role(): void
    {
        $config = new ChangeJournalConfig();
        $this->subject->setChangeJournalConfig($config);

        self::assertSame(
            $config,
            $this->subject->getChangeJournalConfig(),
        );
        self::assertFalse($this->subject->getReplicationConfig()->isProvider());
    }

    public function test_the_replica_id_defaults_to_the_local_identity(): void
    {
        self::assertTrue(
            $this->subject->getReplicationConfig()->getId()->equals(ReplicaId::local()),
        );
    }

    public function test_it_can_override_the_network_config(): void
    {
        $config = NetworkConfig::withPort(1389);
        $this->subject->setNetworkConfig($config);

        self::assertSame(
            $config,
            $this->subject->getNetworkConfig(),
        );
    }

    public function test_it_can_set_the_monitor_snapshot_path(): void
    {
        $this->subject->setMonitorSnapshotPath('/tmp/monitor.json');

        self::assertSame(
            '/tmp/monitor.json',
            $this->subject->getMonitorSnapshotPath(),
        );
    }

    public function test_the_metrics_recorder_defaults_to_a_no_op(): void
    {
        self::assertInstanceOf(
            NullMetricsRecorder::class,
            $this->subject->getMetricsRecorder(),
        );
    }

    public function test_it_can_set_the_metrics_recorder(): void
    {
        $recorder = new InMemoryMetricsRecorder();
        $this->subject->setMetricsRecorder($recorder);

        self::assertSame(
            $recorder,
            $this->subject->getMetricsRecorder(),
        );
    }

    public function test_require_authentication_defaults_to_true(): void
    {
        self::assertTrue($this->subject->isRequireAuthentication());
    }

    public function test_it_can_disable_require_authentication(): void
    {
        $this->subject->setRequireAuthentication(false);

        self::assertFalse($this->subject->isRequireAuthentication());
    }

    public function test_allow_anonymous_defaults_to_false(): void
    {
        self::assertFalse($this->subject->isAllowAnonymous());
    }

    public function test_it_can_allow_anonymous(): void
    {
        $this->subject->setAllowAnonymous(true);

        self::assertTrue($this->subject->isAllowAnonymous());
    }

    public function test_dse_alt_server_is_null_by_default(): void
    {
        self::assertNull($this->subject->getDseAltServer());
    }

    public function test_it_can_set_dse_alt_server(): void
    {
        $this->subject->setDseAltServer('ldap://backup.example.com');

        self::assertSame(
            'ldap://backup.example.com',
            $this->subject->getDseAltServer(),
        );
    }

    public function test_subschema_entry_defaults_to_cn_subschema(): void
    {
        self::assertSame(
            'cn=Subschema',
            $this->subject->getSubschemaEntry()->toString(),
        );
    }

    public function test_the_subschema_entry_comes_from_the_schema_config(): void
    {
        $this->subject->getSchemaConfig()
            ->setSubschemaEntry(new Dn('cn=Subschema,dc=example,dc=com'));

        self::assertSame(
            'cn=Subschema,dc=example,dc=com',
            $this->subject->getSubschemaEntry()->toString(),
        );
    }

    public function test_dse_vendor_name_defaults_to_freedsx(): void
    {
        self::assertSame(
            'FreeDSx',
            $this->subject->getDseVendorName(),
        );
    }

    public function test_it_can_set_dse_vendor_name(): void
    {
        $this->subject->setDseVendorName('Acme');

        self::assertSame(
            'Acme',
            $this->subject->getDseVendorName(),
        );
    }

    public function test_dse_vendor_version_is_null_by_default(): void
    {
        self::assertNull($this->subject->getDseVendorVersion());
    }

    public function test_it_can_set_dse_vendor_version(): void
    {
        $this->subject->setDseVendorVersion('1.0.0');

        self::assertSame(
            '1.0.0',
            $this->subject->getDseVendorVersion(),
        );
    }

    public function test_password_authenticator_is_null_by_default(): void
    {
        self::assertNull($this->subject->getPasswordAuthenticator());
    }

    public function test_it_can_set_password_authenticator(): void
    {
        $authenticator = $this->createMock(PasswordAuthenticatableInterface::class);

        $this->subject->setPasswordAuthenticator($authenticator);

        self::assertSame(
            $authenticator,
            $this->subject->getPasswordAuthenticator(),
        );
    }

    public function test_storage_defaults_to_an_in_memory_config(): void
    {
        self::assertInstanceOf(
            InMemoryStorageConfig::class,
            $this->subject->getStorageConfig(),
        );
    }

    public function test_it_can_set_a_storage_config(): void
    {
        $config = PdoConfig::forSqlite(':memory:');

        $this->subject->setStorageConfig($config);

        self::assertSame(
            $config,
            $this->subject->getStorageConfig(),
        );
    }

    public function test_it_can_be_constructed_with_a_storage_config(): void
    {
        $config = PdoConfig::forSqlite(':memory:');

        self::assertSame(
            $config,
            (new ServerOptions($config))->getStorageConfig(),
        );
    }

    public function test_identity_resolver_is_null_by_default(): void
    {
        self::assertNull($this->subject->getIdentityResolver());
    }

    public function test_it_can_set_identity_resolver(): void
    {
        $resolver = $this->createMock(BindNameResolverInterface::class);

        $this->subject->setIdentityResolver($resolver);

        self::assertSame(
            $resolver,
            $this->subject->getIdentityResolver(),
        );
    }

    public function test_logger_is_null_by_default(): void
    {
        self::assertNull($this->subject->getLogger());
    }

    public function test_it_can_set_logger(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        $this->subject->setLogger($logger);

        self::assertSame(
            $logger,
            $this->subject->getLogger(),
        );
    }

    public function test_server_runner_is_null_by_default(): void
    {
        self::assertNull($this->subject->getServerRunner());
    }

    public function test_it_can_set_server_runner(): void
    {
        $runner = $this->createMock(ServerRunnerInterface::class);

        $this->subject->setServerRunner($runner);

        self::assertSame(
            $runner,
            $this->subject->getServerRunner(),
        );
    }

    public function test_the_runner_defaults_to_pcntl_on_a_single_worker(): void
    {
        self::assertSame(
            RunnerMode::Pcntl,
            $this->subject->getRunnerConfig()->getMode(),
        );
        self::assertSame(
            1,
            $this->subject->getRunnerConfig()->getWorkers(),
        );
    }

    public function test_it_can_set_the_runner(): void
    {
        $this->subject->setRunnerConfig(new RunnerConfig(RunnerMode::Swoole));

        self::assertSame(
            RunnerMode::Swoole,
            $this->subject->getRunnerConfig()->getMode(),
        );
        self::assertTrue($this->subject->isRunnerMode(RunnerMode::Swoole));
    }

    public function test_on_server_ready_is_null_by_default(): void
    {
        self::assertNull($this->subject->getOnServerReady());
    }

    public function test_it_can_set_on_server_ready(): void
    {
        $callback = static function (): void {};

        $this->subject->setOnServerReady($callback);

        self::assertSame(
            $callback,
            $this->subject->getOnServerReady(),
        );
    }

    public function test_max_search_size_defaults_to_1000(): void
    {
        self::assertSame(
            1000,
            $this->subject->getMaxSearchSize(),
        );
    }

    public function test_it_can_set_max_search_size(): void
    {
        $this->subject->setMaxSearchSize(500);

        self::assertSame(
            500,
            $this->subject->getMaxSearchSize(),
        );
    }

    public function test_max_search_time_limit_defaults_to_120(): void
    {
        self::assertSame(
            120,
            $this->subject->getMaxSearchTimeLimit(),
        );
    }

    public function test_it_can_set_max_search_time_limit(): void
    {
        $this->subject->setMaxSearchTimeLimit(60);

        self::assertSame(
            60,
            $this->subject->getMaxSearchTimeLimit(),
        );
    }

    public function test_max_search_page_size_defaults_to_1000(): void
    {
        self::assertSame(
            1000,
            $this->subject->getMaxSearchPageSize(),
        );
    }

    public function test_it_can_set_max_search_page_size(): void
    {
        $this->subject->setMaxSearchPageSize(250);

        self::assertSame(
            250,
            $this->subject->getMaxSearchPageSize(),
        );
    }

    public function test_max_search_lookthrough_defaults_to_5000(): void
    {
        self::assertSame(
            5000,
            $this->subject->getMaxSearchLookthrough(),
        );
    }

    public function test_it_can_set_max_search_lookthrough(): void
    {
        $this->subject->setMaxSearchLookthrough(5000);

        self::assertSame(
            5000,
            $this->subject->getMaxSearchLookthrough(),
        );
    }

    public function test_max_search_paged_lookthrough_defaults_to_0(): void
    {
        self::assertSame(
            0,
            $this->subject->getMaxSearchPagedLookthrough(),
        );
    }

    public function test_it_can_set_max_search_paged_lookthrough(): void
    {
        $this->subject->setMaxSearchPagedLookthrough(100000);

        self::assertSame(
            100000,
            $this->subject->getMaxSearchPagedLookthrough(),
        );
    }

    public function test_search_limit_rules_default_to_empty(): void
    {
        self::assertTrue($this->subject->getSearchLimitRules()->isEmpty());
    }

    public function test_it_can_set_search_limit_rules(): void
    {
        $rules = (new SearchLimitRules())->withRules(
            SearchLimitRule::for(Subject::anonymous(), new SearchLimits(maxSearchSize: 10)),
        );
        $this->subject->setSearchLimitRules($rules);

        self::assertSame(
            $rules,
            $this->subject->getSearchLimitRules(),
        );
    }

    public function test_make_search_limits_reflects_current_options(): void
    {
        $this->subject
            ->setMaxSearchSize(500)
            ->setMaxSearchTimeLimit(60)
            ->setMaxSearchPageSize(250)
            ->setMaxSearchLookthrough(5000)
            ->setMaxSearchPagedLookthrough(100000)
            ->setMaxPagingSessions(5);

        self::assertEquals(
            new SearchLimits(
                maxSearchSize: 500,
                maxSearchTimeLimit: 60,
                maxSearchPageSize: 250,
                maxSearchLookthrough: 5000,
                maxSearchPagedLookthrough: 100000,
                maxPagingSessions: 5,
            ),
            $this->subject->makeSearchLimits(),
        );
    }

    public function test_the_password_config_is_round_tripped(): void
    {
        $config = new PasswordConfig();

        $this->subject->setPasswordConfig($config);

        self::assertSame(
            $config,
            $this->subject->getPasswordConfig(),
        );
    }

    public function test_the_default_schema_ships_the_expected_schemas(): void
    {
        $schema = $this->subject->getSchema();

        self::assertNotNull($schema->getAttributeType(AttributeTypeOid::NAME_CN));
        self::assertNotNull($schema->getAttributeType(NisAttributeTypeOid::NAME_UID_NUMBER));
        self::assertNotNull($schema->getAttributeType(PasswordPolicyOid::NAME_PWD_MIN_LENGTH));
        self::assertNotNull($schema->getObjectClass(PasswordPolicyOid::NAME_PWD_POLICY));
    }

    /**
     * The password policy schema is unconditional, so the order configuration happens in cannot change it.
     */
    public function test_the_schema_carries_password_policy_whenever_a_policy_is_configured(): void
    {
        $this->subject->getSchema();
        $this->subject->getPasswordConfig()
            ->setPolicy(new PasswordPolicy());

        self::assertNotNull(
            $this->subject->getSchema()
                ->getAttributeType(PasswordPolicyOid::NAME_PWD_CHANGED_TIME),
        );
    }

    public function test_a_custom_source_list_still_carries_password_policy(): void
    {
        $this->subject->getPasswordConfig()
            ->setPolicy(new PasswordPolicy());
        $this->subject->getSchemaConfig()
            ->setSources(SchemaResource::Core, SchemaResource::PasswordPolicy);

        self::assertNotNull(
            $this->subject->getSchema()
                ->getAttributeType(PasswordPolicyOid::NAME_PWD_CHANGED_TIME),
        );
    }

    public function test_the_resolved_schema_is_reused_until_the_sources_change(): void
    {
        $first = $this->subject->getSchema();

        self::assertSame(
            $first,
            $this->subject->getSchema(),
        );

        $this->subject->getSchemaConfig()
            ->addSource(SchemaResource::Core);

        self::assertNotSame(
            $first,
            $this->subject->getSchema(),
        );
    }

    public function test_it_accepts_all_defined_mechanism_constants(): void
    {
        $this->subject->setSaslMechanisms(
            ServerOptions::SASL_PLAIN,
            ServerOptions::SASL_CRAM_MD5,
            ServerOptions::SASL_DIGEST_MD5,
            ServerOptions::SASL_SCRAM_SHA_1,
            ServerOptions::SASL_SCRAM_SHA_1_PLUS,
            ServerOptions::SASL_SCRAM_SHA_224,
            ServerOptions::SASL_SCRAM_SHA_224_PLUS,
            ServerOptions::SASL_SCRAM_SHA_256,
            ServerOptions::SASL_SCRAM_SHA_256_PLUS,
            ServerOptions::SASL_SCRAM_SHA_384,
            ServerOptions::SASL_SCRAM_SHA_384_PLUS,
            ServerOptions::SASL_SCRAM_SHA_512,
            ServerOptions::SASL_SCRAM_SHA_512_PLUS,
            ServerOptions::SASL_SCRAM_SHA3_512,
            ServerOptions::SASL_SCRAM_SHA3_512_PLUS,
        );

        self::assertCount(
            15,
            $this->subject->getSaslMechanisms(),
        );
    }

    public function test_setting_administrators_after_reading_access_control_rebuilds_the_secure_default(): void
    {
        $before = $this->subject->getAccessControl();

        $this->subject->setAdministrators(
            Subject::dn('uid=admin,dc=foo,dc=bar'),
        );

        self::assertNotSame(
            $before,
            $this->subject->getAccessControl(),
        );
    }

    public function test_setting_administrators_after_reading_acl_rules_rebuilds_the_secure_default(): void
    {
        $before = $this->subject->getAclRules();

        $this->subject->setAdministrators(
            Subject::dn('uid=admin,dc=foo,dc=bar'),
        );

        self::assertNotSame(
            $before,
            $this->subject->getAclRules(),
        );
    }

    public function test_setting_acl_rules_after_reading_access_control_rebuilds_it(): void
    {
        $before = $this->subject->getAccessControl();

        $this->subject->setAclRules(
            AclRules::fromEmpty(),
        );

        self::assertNotSame(
            $before,
            $this->subject->getAccessControl(),
        );
    }
}
