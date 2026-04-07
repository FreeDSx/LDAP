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
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
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
            $this->subject->getIp()
        );
    }

    public function test_it_can_set_ip(): void
    {
        $this->subject->setIp('127.0.0.1');

        self::assertSame(
            '127.0.0.1',
            $this->subject->getIp()
        );
    }

    public function test_port_defaults_to_389(): void
    {
        self::assertSame(
            389,
            $this->subject->getPort()
        );
    }

    public function test_it_can_set_port(): void
    {
        $this->subject->setPort(33389);

        self::assertSame(
            33389,
            $this->subject->getPort()
        );
    }

    public function test_transport_defaults_to_tcp(): void
    {
        self::assertSame(
            'tcp',
            $this->subject->getTransport()
        );
    }

    public function test_it_can_set_transport(): void
    {
        $this->subject->setTransport('unix');

        self::assertSame(
            'unix',
            $this->subject->getTransport()
        );
    }

    public function test_unix_socket_has_a_default(): void
    {
        self::assertSame(
            '/var/run/ldap.socket',
            $this->subject->getUnixSocket()
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
            $this->subject->getIdleTimeout()
        );
    }

    public function test_it_can_set_idle_timeout(): void
    {
        $this->subject->setIdleTimeout(120);

        self::assertSame(
            120,
            $this->subject->getIdleTimeout()
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
            $this->subject->getSslCert()
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
            $this->subject->getSslCertKey()
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
            $this->subject->getSslCertPassphrase()
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
            $this->subject->getDseAltServer()
        );
    }

    public function test_subschema_entry_defaults_to_cn_subschema(): void
    {
        self::assertSame(
            'cn=Subschema',
            $this->subject->getSubschemaEntry()->toString()
        );
    }

    public function test_it_can_set_subschema_entry(): void
    {
        $this->subject->setSubschemaEntry(new Dn('cn=Subschema,dc=example,dc=com'));

        self::assertSame(
            'cn=Subschema,dc=example,dc=com',
            $this->subject->getSubschemaEntry()->toString()
        );
    }

    public function test_dse_naming_contexts_has_a_default(): void
    {
        self::assertSame(
            ['dc=FreeDSx,dc=local'],
            $this->subject->getDseNamingContexts()
        );
    }

    public function test_it_can_set_dse_naming_contexts(): void
    {
        $this->subject->setDseNamingContexts('dc=example,dc=com', 'dc=other,dc=com');

        self::assertSame(
            ['dc=example,dc=com', 'dc=other,dc=com'],
            $this->subject->getDseNamingContexts()
        );
    }

    public function test_dse_vendor_name_defaults_to_freedsx(): void
    {
        self::assertSame(
            'FreeDSx',
            $this->subject->getDseVendorName()
        );
    }

    public function test_it_can_set_dse_vendor_name(): void
    {
        $this->subject->setDseVendorName('Acme');

        self::assertSame(
            'Acme',
            $this->subject->getDseVendorName()
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
            $this->subject->getDseVendorVersion()
        );
    }

    public function test_backend_is_null_by_default(): void
    {
        self::assertNull($this->subject->getBackend());
    }

    public function test_it_can_set_backend(): void
    {
        $backend = $this->createMock(LdapBackendInterface::class);

        $this->subject->setBackend($backend);

        self::assertSame(
            $backend,
            $this->subject->getBackend()
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
            $this->subject->getPasswordAuthenticator()
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
            $this->subject->getRootDseHandler()
        );
    }

    public function test_write_handlers_are_empty_by_default(): void
    {
        self::assertSame(
            [],
            $this->subject->getWriteHandlers()
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
            $this->subject->getWriteHandlers()
        );
    }

    public function test_filter_evaluator_is_null_by_default(): void
    {
        self::assertNull($this->subject->getFilterEvaluator());
    }

    public function test_it_can_set_filter_evaluator(): void
    {
        $evaluator = $this->createMock(FilterEvaluatorInterface::class);

        $this->subject->setFilterEvaluator($evaluator);

        self::assertSame(
            $evaluator,
            $this->subject->getFilterEvaluator()
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
            $this->subject->getLogger()
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
            $this->subject->getServerRunner()
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
            $this->subject->getSocketAcceptTimeout()
        );
    }

    public function test_it_can_set_socket_accept_timeout(): void
    {
        $this->subject->setSocketAcceptTimeout(1.0);

        self::assertSame(
            1.0,
            $this->subject->getSocketAcceptTimeout()
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
            $this->subject->getOnServerReady()
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
