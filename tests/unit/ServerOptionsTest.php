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
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\DefaultPasswordQualityChecker;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\PasswordQualityCheckerInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Sasl\External\ExternalCredentialMapperInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
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
use FreeDSx\Ldap\Server\TlsVersion;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\ReplicaConfig;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

final class ServerOptionsTest extends TestCase
{
    private ServerOptions $subject;

    protected function setUp(): void
    {
        $this->subject = new ServerOptions();
    }

    public function test_a_default_server_is_not_a_read_only_replica(): void
    {
        self::assertFalse($this->subject->isReadOnly());
        self::assertNull($this->subject->getReplicaConfig());
    }

    public function test_for_replica_configures_a_read_only_replica(): void
    {
        $config = new ReplicaConfig(new ClientOptions());
        $options = ServerOptions::forReplica(
            $config,
            PdoConfig::forSqlite(':memory:'),
        );

        self::assertTrue($options->isReadOnly());
        self::assertSame(
            $config,
            $options->getReplicaConfig(),
        );
    }

    public function test_privileged_controls_have_the_expected_defaults(): void
    {
        self::assertSame(
            [
                Control::OID_RELAX_RULES,
                Control::OID_SYNC_REQUEST,
            ],
            $this->subject->getPrivilegedControls(),
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

    public function test_max_connections_defaults_to_zero(): void
    {
        self::assertSame(0, $this->subject->getMaxConnections());
    }

    public function test_it_can_set_max_connections(): void
    {
        $this->subject->setMaxConnections(500);

        self::assertSame(500, $this->subject->getMaxConnections());
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

    public function test_sync_is_disabled_by_default(): void
    {
        self::assertFalse($this->subject->isSyncEnabled());
    }

    public function test_it_can_enable_sync(): void
    {
        $this->subject->setSyncEnabled(true);

        self::assertTrue($this->subject->isSyncEnabled());
    }

    public function test_the_change_journal_config_defaults_to_a_usable_config(): void
    {
        self::assertTrue(
            $this->subject->getChangeJournalConfig()->origin->equals(new ReplicaId('local')),
        );
    }

    public function test_it_can_override_the_change_journal_config(): void
    {
        $config = new ChangeJournalConfig(new ReplicaId('node-a'));
        $this->subject->setChangeJournalConfig($config);

        self::assertSame(
            $config,
            $this->subject->getChangeJournalConfig(),
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

    public function test_shutdown_timeout_defaults_to_fifteen_seconds(): void
    {
        self::assertSame(15, $this->subject->getShutdownTimeout());
    }

    public function test_it_can_set_shutdown_timeout(): void
    {
        $this->subject->setShutdownTimeout(30);

        self::assertSame(30, $this->subject->getShutdownTimeout());
    }

    public function test_ip_defaults_to_all_interfaces(): void
    {
        self::assertSame(
            '0.0.0.0',
            $this->subject->getIp(),
        );
    }

    public function test_it_can_set_ip(): void
    {
        $this->subject->setIp('127.0.0.1');

        self::assertSame(
            '127.0.0.1',
            $this->subject->getIp(),
        );
    }

    public function test_port_defaults_to_389(): void
    {
        self::assertSame(
            389,
            $this->subject->getPort(),
        );
    }

    public function test_it_can_set_port(): void
    {
        $this->subject->setPort(33389);

        self::assertSame(
            33389,
            $this->subject->getPort(),
        );
    }

    public function test_transport_defaults_to_tcp(): void
    {
        self::assertSame(
            'tcp',
            $this->subject->getTransport(),
        );
    }

    public function test_it_can_set_transport(): void
    {
        $this->subject->setTransport('unix');

        self::assertSame(
            'unix',
            $this->subject->getTransport(),
        );
    }

    public function test_unix_socket_has_a_default(): void
    {
        self::assertSame(
            '/var/run/ldap.socket',
            $this->subject->getUnixSocket(),
        );
    }

    public function test_it_can_set_unix_socket(): void
    {
        $this->subject->setUnixSocket('/tmp/ldap.sock');

        self::assertSame('/tmp/ldap.sock', $this->subject->getUnixSocket());
    }

    public function test_idle_timeout_defaults_to_600(): void
    {
        self::assertSame(
            600,
            $this->subject->getIdleTimeout(),
        );
    }

    public function test_it_can_set_idle_timeout(): void
    {
        $this->subject->setIdleTimeout(120);

        self::assertSame(
            120,
            $this->subject->getIdleTimeout(),
        );
    }

    public function test_write_timeout_defaults_to_600(): void
    {
        self::assertSame(
            600,
            $this->subject->getWriteTimeout(),
        );
    }

    public function test_it_can_set_write_timeout(): void
    {
        $this->subject->setWriteTimeout(0);

        self::assertSame(
            0,
            $this->subject->getWriteTimeout(),
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

    public function test_ssl_is_disabled_by_default(): void
    {
        self::assertFalse($this->subject->isUseSsl());
    }

    public function test_it_can_enable_ssl(): void
    {
        $this->subject->setUseSsl(true);

        self::assertTrue($this->subject->isUseSsl());
    }

    public function test_ssl_cert_is_null_by_default(): void
    {
        self::assertNull($this->subject->getSslCert());
    }

    public function test_it_can_set_ssl_cert(): void
    {
        $this->subject->setSslCert('/path/to/cert.pem');

        self::assertSame(
            '/path/to/cert.pem',
            $this->subject->getSslCert(),
        );
    }

    public function test_ssl_cert_key_is_null_by_default(): void
    {
        self::assertNull($this->subject->getSslCertKey());
    }

    public function test_it_can_set_ssl_cert_key(): void
    {
        $this->subject->setSslCertKey('/path/to/key.pem');

        self::assertSame(
            '/path/to/key.pem',
            $this->subject->getSslCertKey(),
        );
    }

    public function test_ssl_cert_passphrase_is_null_by_default(): void
    {
        self::assertNull($this->subject->getSslCertPassphrase());
    }

    public function test_it_can_set_ssl_cert_passphrase(): void
    {
        $this->subject->setSslCertPassphrase('secret');

        self::assertSame(
            'secret',
            $this->subject->getSslCertPassphrase(),
        );
    }

    public function test_min_tls_version_defaults_to_1_2(): void
    {
        self::assertSame(
            TlsVersion::Tls1_2,
            $this->subject->getMinTlsVersion(),
        );
    }

    public function test_it_can_set_min_tls_version(): void
    {
        $this->subject->setMinTlsVersion(TlsVersion::Tls1_3);

        self::assertSame(
            TlsVersion::Tls1_3,
            $this->subject->getMinTlsVersion(),
        );
    }

    public function test_ssl_ciphers_default_to_default(): void
    {
        self::assertSame(
            'DEFAULT',
            $this->subject->getSslCiphers(),
        );
    }

    public function test_it_can_set_ssl_ciphers(): void
    {
        $this->subject->setSslCiphers('ECDHE-RSA-AES128-GCM-SHA256');

        self::assertSame(
            'ECDHE-RSA-AES128-GCM-SHA256',
            $this->subject->getSslCiphers(),
        );
    }

    public function test_ssl_validate_cert_is_disabled_by_default(): void
    {
        self::assertFalse($this->subject->isSslValidateCert());
    }

    public function test_it_can_enable_ssl_validate_cert(): void
    {
        $this->subject->setSslValidateCert(true);

        self::assertTrue($this->subject->isSslValidateCert());
    }

    public function test_ssl_allow_self_signed_is_null_by_default(): void
    {
        self::assertNull($this->subject->getSslAllowSelfSigned());
    }

    public function test_it_can_set_ssl_allow_self_signed(): void
    {
        $this->subject->setSslAllowSelfSigned(true);

        self::assertTrue($this->subject->getSslAllowSelfSigned());
    }

    public function test_ssl_ca_cert_is_null_by_default(): void
    {
        self::assertNull($this->subject->getSslCaCert());
    }

    public function test_it_can_set_ssl_ca_cert(): void
    {
        $this->subject->setSslCaCert('/path/to/ca.pem');

        self::assertSame(
            '/path/to/ca.pem',
            $this->subject->getSslCaCert(),
        );
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

    public function test_it_can_set_subschema_entry(): void
    {
        $this->subject->setSubschemaEntry(new Dn('cn=Subschema,dc=example,dc=com'));

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

    public function test_the_runner_defaults_to_pcntl(): void
    {
        self::assertSame(
            RunnerMode::Pcntl,
            $this->subject->getRunner(),
        );
    }

    public function test_it_can_set_the_runner(): void
    {
        $this->subject->setRunner(RunnerMode::Swoole);

        self::assertSame(
            RunnerMode::Swoole,
            $this->subject->getRunner(),
        );
    }

    public function test_socket_accept_timeout_defaults_to_half_second(): void
    {
        self::assertSame(
            0.5,
            $this->subject->getSocketAcceptTimeout(),
        );
    }

    public function test_it_can_set_socket_accept_timeout(): void
    {
        $this->subject->setSocketAcceptTimeout(1.0);

        self::assertSame(
            1.0,
            $this->subject->getSocketAcceptTimeout(),
        );
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
            ->setMaxSearchPagedLookthrough(100000);

        self::assertEquals(
            new SearchLimits(
                maxSearchSize: 500,
                maxSearchTimeLimit: 60,
                maxSearchPageSize: 250,
                maxSearchLookthrough: 5000,
                maxSearchPagedLookthrough: 100000,
            ),
            $this->subject->makeSearchLimits(),
        );
    }

    public function test_password_policy_is_disabled_by_default(): void
    {
        self::assertFalse($this->subject->isPasswordPolicyEnabled());
        self::assertNull($this->subject->getPasswordPolicy());
        self::assertNull($this->subject->getDefaultPasswordPolicyDn());
    }

    public function test_setting_in_memory_policy_enables_the_feature(): void
    {
        $policy = new PasswordPolicy(quality: new PasswordQualityRules(minLength: 8));

        $this->subject->setPasswordPolicy($policy);

        self::assertTrue($this->subject->isPasswordPolicyEnabled());
        self::assertSame(
            $policy,
            $this->subject->getPasswordPolicy(),
        );
    }

    public function test_setting_default_policy_dn_enables_the_feature(): void
    {
        $dn = new Dn('cn=default,ou=policies,dc=example,dc=com');

        $this->subject->setDefaultPasswordPolicyDn($dn);

        self::assertTrue($this->subject->isPasswordPolicyEnabled());
        self::assertSame(
            $dn,
            $this->subject->getDefaultPasswordPolicyDn(),
        );
    }

    public function test_schema_omits_password_policy_attributes_when_feature_disabled(): void
    {
        $schema = $this->subject->getSchema();

        self::assertNull($schema->getAttributeType(PasswordPolicyOid::NAME_PWD_MIN_LENGTH));
        self::assertNull($schema->getObjectClass(PasswordPolicyOid::NAME_PWD_POLICY));
    }

    public function test_schema_includes_password_policy_attributes_when_feature_enabled(): void
    {
        $this->subject->setPasswordPolicy(new PasswordPolicy());

        $schema = $this->subject->getSchema();

        self::assertNotNull($schema->getAttributeType(PasswordPolicyOid::NAME_PWD_MIN_LENGTH));
        self::assertNotNull($schema->getObjectClass(PasswordPolicyOid::NAME_PWD_POLICY));
    }

    public function test_password_hash_scheme_defaults_to_bcrypt(): void
    {
        self::assertSame(
            PasswordHashScheme::Bcrypt,
            $this->subject->getPasswordHashScheme(),
        );
    }

    public function test_setting_password_hash_scheme_is_round_tripped(): void
    {
        $this->subject->setPasswordHashScheme(PasswordHashScheme::Argon2);

        self::assertSame(
            PasswordHashScheme::Argon2,
            $this->subject->getPasswordHashScheme(),
        );
    }

    public function test_password_quality_checker_defaults_to_the_built_in_checker(): void
    {
        self::assertInstanceOf(
            DefaultPasswordQualityChecker::class,
            $this->subject->getPasswordQualityChecker(),
        );
    }

    public function test_setting_password_quality_checker_is_round_tripped(): void
    {
        $custom = new class implements PasswordQualityCheckerInterface {
            public function check(
                string $plain,
                PasswordQualityRules $rules,
            ): ?int {
                return null;
            }
        };

        $this->subject->setPasswordQualityChecker($custom);

        self::assertSame(
            $custom,
            $this->subject->getPasswordQualityChecker(),
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
