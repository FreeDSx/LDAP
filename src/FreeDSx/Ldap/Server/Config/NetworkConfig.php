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

namespace FreeDSx\Ldap\Server\Config;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\TlsVersion;

use function sprintf;

/**
 * The listener socket and TLS settings a server binds and accepts connections with.
 *
 * @api
 */
final class NetworkConfig
{
    private string $ip = '0.0.0.0';

    private int $port = 389;

    private string $unixSocket = '/var/run/ldap.socket';

    private string $transport = 'tcp';

    private int $idleTimeout = 600;

    /**
     * Disconnect a client whose response send makes no progress for this many seconds (a stalled reader).
     */
    private int $writeTimeout = 30;

    /**
     * Disconnect a client whose request takes longer than this many seconds to finish arriving.
     */
    private int $requestReadTimeout = 30;

    /**
     * Seconds (fractional) to wait for a new client connection before re-checking server state.
     */
    private float $socketAcceptTimeout = 0.5;

    /**
     * Seconds to wait for active connections to close gracefully before forcing them closed on shutdown.
     */
    private int $shutdownTimeout = 15;

    /**
     * The largest incoming request PDU accepted, in bytes (2.5 MiB); 0 disables the limit.
     */
    private int $maxRequestSize = 2_621_440;

    /**
     * The largest request PDU accepted without an authenticated bind, in bytes (256 KiB); 0 disables the limit.
     */
    private int $maxAnonymousRequestSize = 262_144;

    /**
     * The most ASN.1 elements an incoming request may hold; 0 disables the limit.
     */
    private int $maxRequestElements = 100_000;

    /**
     * The maximum number of concurrent connections the server will accept; zero means no limit.
     */
    private int $maxConnections = 1024;

    private bool $useSsl = false;

    private ?string $sslCert = null;

    private ?string $sslCertKey = null;

    private ?string $sslCertPassphrase = null;

    private TlsVersion $minTlsVersion = TlsVersion::Tls1_2;

    private string $sslCiphers = 'DEFAULT';

    private bool $sslValidateCert = false;

    private ?bool $sslAllowSelfSigned = null;

    private ?string $sslCaCert = null;

    private int $sslHandshakeTimeout = 5;

    /**
     * Convenience constructor for the common case of only choosing the listening port.
     */
    public static function withPort(int $port): self
    {
        return (new self())->setPort($port);
    }

    public function getIp(): string
    {
        return $this->ip;
    }

    public function setIp(string $ip): self
    {
        $this->ip = $ip;

        return $this;
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function setPort(int $port): self
    {
        $this->port = $port;

        return $this;
    }

    public function getUnixSocket(): string
    {
        return $this->unixSocket;
    }

    public function setUnixSocket(string $unixSocket): self
    {
        $this->unixSocket = $unixSocket;

        return $this;
    }

    public function getTransport(): string
    {
        return $this->transport;
    }

    public function setTransport(string $transport): self
    {
        $this->transport = $transport;

        return $this;
    }

    /**
     * Whether connections arrive over a local socket rather than a network.
     */
    public function isUnixSocket(): bool
    {
        return $this->transport === 'unix';
    }

    public function getIdleTimeout(): int
    {
        return $this->idleTimeout;
    }

    /**
     * @param int $idleTimeout the time in seconds, or -1 to never time out.
     */
    public function setIdleTimeout(int $idleTimeout): self
    {
        $this->idleTimeout = $idleTimeout;

        return $this;
    }

    public function getWriteTimeout(): int
    {
        return $this->writeTimeout;
    }

    /**
     * @param int $writeTimeout the time in seconds, or 0 to disable the timeout.
     */
    public function setWriteTimeout(int $writeTimeout): self
    {
        $this->writeTimeout = $writeTimeout;

        return $this;
    }

    public function getRequestReadTimeout(): int
    {
        return $this->requestReadTimeout;
    }

    /**
     * @param int $requestReadTimeout the time in seconds, or 0 to disable the timeout.
     * @throws InvalidArgumentException when the timeout is negative
     */
    public function setRequestReadTimeout(int $requestReadTimeout): self
    {
        self::assertNotNegative(
            $requestReadTimeout,
            'The request read timeout',
        );
        $this->requestReadTimeout = $requestReadTimeout;

        return $this;
    }

    public function getSocketAcceptTimeout(): float
    {
        return $this->socketAcceptTimeout;
    }

    /**
     * @param float $socketAcceptTimeout the time in seconds, which may be fractional.
     */
    public function setSocketAcceptTimeout(float $socketAcceptTimeout): self
    {
        $this->socketAcceptTimeout = $socketAcceptTimeout;

        return $this;
    }

    public function getShutdownTimeout(): int
    {
        return $this->shutdownTimeout;
    }

    /**
     * @param int $shutdownTimeout the time in seconds.
     */
    public function setShutdownTimeout(int $shutdownTimeout): self
    {
        $this->shutdownTimeout = $shutdownTimeout;

        return $this;
    }

    public function getMaxRequestSize(): int
    {
        return $this->maxRequestSize;
    }

    /**
     * @param int $maxRequestSize the size in bytes, or 0 to disable the limit.
     * @throws InvalidArgumentException when the limit is negative
     */
    public function setMaxRequestSize(int $maxRequestSize): self
    {
        self::assertNotNegative(
            $maxRequestSize,
            'The request size limit',
        );
        $this->maxRequestSize = $maxRequestSize;

        return $this;
    }

    public function getMaxAnonymousRequestSize(): int
    {
        return $this->maxAnonymousRequestSize;
    }

    /**
     * @param int $maxAnonymousRequestSize the size in bytes, or 0 to disable the limit.
     * @throws InvalidArgumentException when the limit is negative
     */
    public function setMaxAnonymousRequestSize(int $maxAnonymousRequestSize): self
    {
        self::assertNotNegative(
            $maxAnonymousRequestSize,
            'The anonymous request size limit',
        );
        $this->maxAnonymousRequestSize = $maxAnonymousRequestSize;

        return $this;
    }

    public function getMaxRequestElements(): int
    {
        return $this->maxRequestElements;
    }

    /**
     * @param int $maxRequestElements the number of ASN.1 elements, or 0 to disable the limit.
     * @throws InvalidArgumentException when the limit is negative
     */
    public function setMaxRequestElements(int $maxRequestElements): self
    {
        self::assertNotNegative(
            $maxRequestElements,
            'The request element limit',
        );
        $this->maxRequestElements = $maxRequestElements;

        return $this;
    }

    public function getMaxConnections(): int
    {
        return $this->maxConnections;
    }

    /**
     * @param int $maxConnections the number of concurrent connections, or 0 for no limit.
     */
    public function setMaxConnections(int $maxConnections): self
    {
        $this->maxConnections = $maxConnections;

        return $this;
    }

    public function isUseSsl(): bool
    {
        return $this->useSsl;
    }

    public function setUseSsl(bool $useSsl): self
    {
        $this->useSsl = $useSsl;

        return $this;
    }

    public function getSslCert(): ?string
    {
        return $this->sslCert;
    }

    public function setSslCert(?string $sslCert): self
    {
        $this->sslCert = $sslCert;

        return $this;
    }

    public function getSslCertKey(): ?string
    {
        return $this->sslCertKey;
    }

    public function setSslCertKey(?string $sslCertKey): self
    {
        $this->sslCertKey = $sslCertKey;

        return $this;
    }

    public function getSslCertPassphrase(): ?string
    {
        return $this->sslCertPassphrase;
    }

    public function setSslCertPassphrase(?string $sslCertPassphrase): self
    {
        $this->sslCertPassphrase = $sslCertPassphrase;

        return $this;
    }

    public function getMinTlsVersion(): TlsVersion
    {
        return $this->minTlsVersion;
    }

    public function setMinTlsVersion(TlsVersion $minTlsVersion): self
    {
        $this->minTlsVersion = $minTlsVersion;

        return $this;
    }

    public function getSslCiphers(): string
    {
        return $this->sslCiphers;
    }

    public function setSslCiphers(string $sslCiphers): self
    {
        $this->sslCiphers = $sslCiphers;

        return $this;
    }

    public function isSslValidateCert(): bool
    {
        return $this->sslValidateCert;
    }

    public function setSslValidateCert(bool $sslValidateCert): self
    {
        $this->sslValidateCert = $sslValidateCert;

        return $this;
    }

    public function getSslHandshakeTimeout(): int
    {
        return $this->sslHandshakeTimeout;
    }

    /**
     * @param int $sslHandshakeTimeout the time in seconds.
     */
    public function setSslHandshakeTimeout(int $sslHandshakeTimeout): self
    {
        $this->sslHandshakeTimeout = $sslHandshakeTimeout;

        return $this;
    }

    public function getSslAllowSelfSigned(): ?bool
    {
        return $this->sslAllowSelfSigned;
    }

    public function setSslAllowSelfSigned(?bool $sslAllowSelfSigned): self
    {
        $this->sslAllowSelfSigned = $sslAllowSelfSigned;

        return $this;
    }

    public function getSslCaCert(): ?string
    {
        return $this->sslCaCert;
    }

    public function setSslCaCert(?string $sslCaCert): self
    {
        $this->sslCaCert = $sslCaCert;

        return $this;
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function assertNotNegative(
        int $limit,
        string $name,
    ): void {
        if ($limit >= 0) {
            return;
        }

        throw new InvalidArgumentException(sprintf(
            '%s cannot be negative, but received %d.',
            $name,
            $limit,
        ));
    }
}
