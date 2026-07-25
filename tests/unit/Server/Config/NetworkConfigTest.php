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

namespace Tests\Unit\FreeDSx\Ldap\Server\Config;

use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\TlsVersion;
use PHPUnit\Framework\TestCase;

final class NetworkConfigTest extends TestCase
{
    private NetworkConfig $subject;

    protected function setUp(): void
    {
        $this->subject = new NetworkConfig();
    }

    public function test_with_port_sets_only_the_port(): void
    {
        $config = NetworkConfig::withPort(33389);

        self::assertSame(
            33389,
            $config->getPort(),
        );
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

    public function test_max_request_size_defaults_to_five_mib(): void
    {
        self::assertSame(
            5_242_880,
            $this->subject->getMaxRequestSize(),
        );
    }

    public function test_it_can_set_max_request_size(): void
    {
        $this->subject->setMaxRequestSize(1_048_576);

        self::assertSame(
            1_048_576,
            $this->subject->getMaxRequestSize(),
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
}
