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
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\DefaultPasswordQualityChecker;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\PasswordQualityCheckerInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluator;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\SearchLimits;
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

    public function test_backend_is_null_by_default(): void
    {
        self::assertNull($this->subject->getBackend());
    }

    public function test_it_can_set_backend(): void
    {
        $backend = $this->createMock(WritableLdapBackendInterface::class);

        $this->subject->setBackend($backend);

        self::assertSame(
            $backend,
            $this->subject->getBackend(),
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

    public function test_root_dse_handler_is_null_by_default(): void
    {
        self::assertNull($this->subject->getRootDseHandler());
    }

    public function test_it_can_set_root_dse_handler(): void
    {
        $handler = $this->createMock(RootDseHandlerInterface::class);

        $this->subject->setRootDseHandler($handler);

        self::assertSame(
            $handler,
            $this->subject->getRootDseHandler(),
        );
    }

    public function test_write_handlers_are_empty_by_default(): void
    {
        self::assertSame(
            [],
            $this->subject->getWriteHandlers(),
        );
    }

    public function test_it_can_add_write_handlers(): void
    {
        $handler1 = $this->createMock(WriteHandlerInterface::class);
        $handler2 = $this->createMock(WriteHandlerInterface::class);

        $this->subject
            ->addWriteHandler($handler1)
            ->addWriteHandler($handler2);

        self::assertSame(
            [$handler1, $handler2],
            $this->subject->getWriteHandlers(),
        );
    }

    public function test_filter_evaluator_defaults_to_a_filter_evaluator_instance(): void
    {
        self::assertInstanceOf(
            FilterEvaluator::class,
            $this->subject->getFilterEvaluator(),
        );
    }

    public function test_it_can_set_filter_evaluator(): void
    {
        $evaluator = $this->createMock(FilterEvaluatorInterface::class);

        $this->subject->setFilterEvaluator($evaluator);

        self::assertSame(
            $evaluator,
            $this->subject->getFilterEvaluator(),
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

    public function test_swoole_runner_is_disabled_by_default(): void
    {
        self::assertFalse($this->subject->getUseSwooleRunner());
    }

    public function test_it_can_enable_swoole_runner(): void
    {
        $this->subject->setUseSwooleRunner(true);

        self::assertTrue($this->subject->getUseSwooleRunner());
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

    public function test_make_search_limits_reflects_current_options(): void
    {
        $this->subject
            ->setMaxSearchSize(500)
            ->setMaxSearchTimeLimit(60)
            ->setMaxSearchPageSize(250);

        self::assertEquals(
            new SearchLimits(
                maxSearchSize: 500,
                maxSearchTimeLimit: 60,
                maxSearchPageSize: 250,
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
}
