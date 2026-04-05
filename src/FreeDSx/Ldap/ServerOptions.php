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

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use Psr\Log\LoggerInterface;

final class ServerOptions
{
    public const SASL_PLAIN = 'PLAIN';

    public const SASL_CRAM_MD5 = 'CRAM-MD5';

    public const SASL_DIGEST_MD5 = 'DIGEST-MD5';

    public const SASL_SCRAM_SHA_1 = 'SCRAM-SHA-1';

    public const SASL_SCRAM_SHA_1_PLUS = 'SCRAM-SHA-1-PLUS';

    public const SASL_SCRAM_SHA_224 = 'SCRAM-SHA-224';

    public const SASL_SCRAM_SHA_224_PLUS = 'SCRAM-SHA-224-PLUS';

    public const SASL_SCRAM_SHA_256 = 'SCRAM-SHA-256';

    public const SASL_SCRAM_SHA_256_PLUS = 'SCRAM-SHA-256-PLUS';

    public const SASL_SCRAM_SHA_384 = 'SCRAM-SHA-384';

    public const SASL_SCRAM_SHA_384_PLUS = 'SCRAM-SHA-384-PLUS';

    public const SASL_SCRAM_SHA_512 = 'SCRAM-SHA-512';

    public const SASL_SCRAM_SHA_512_PLUS = 'SCRAM-SHA-512-PLUS';

    public const SASL_SCRAM_SHA3_512 = 'SCRAM-SHA3-512';

    public const SASL_SCRAM_SHA3_512_PLUS = 'SCRAM-SHA3-512-PLUS';

    private const SUPPORTED_SASL_MECHANISMS = [
        self::SASL_PLAIN,
        self::SASL_CRAM_MD5,
        self::SASL_DIGEST_MD5,
        self::SASL_SCRAM_SHA_1,
        self::SASL_SCRAM_SHA_1_PLUS,
        self::SASL_SCRAM_SHA_224,
        self::SASL_SCRAM_SHA_224_PLUS,
        self::SASL_SCRAM_SHA_256,
        self::SASL_SCRAM_SHA_256_PLUS,
        self::SASL_SCRAM_SHA_384,
        self::SASL_SCRAM_SHA_384_PLUS,
        self::SASL_SCRAM_SHA_512,
        self::SASL_SCRAM_SHA_512_PLUS,
        self::SASL_SCRAM_SHA3_512,
        self::SASL_SCRAM_SHA3_512_PLUS,
    ];

    private string $ip = '0.0.0.0';

    private int $port = 389;

    private string $unixSocket = '/var/run/ldap.socket';

    private string $transport = 'tcp';

    private int $idleTimeout = 600;

    private bool $requireAuthentication = true;

    private bool $allowAnonymous = false;

    private bool $useSsl = false;

    private ?string $sslCert = null;

    private ?string $sslCertKey = null;

    private ?string $sslCertPassphrase = null;

    private ?string $dseAltServer = null;

    private ?Dn $subschemaEntry = null;

    /**
     * @var string[]
     */
    private array $dseNamingContexts = ['dc=FreeDSx,dc=local'];

    private string $dseVendorName = 'FreeDSx';

    private ?string $dseVendorVersion = null;

    private ?LdapBackendInterface $backend = null;

    private ?PasswordAuthenticatableInterface $passwordAuthenticator = null;

    private ?RootDseHandlerInterface $rootDseHandler = null;

    /**
     * @var WriteHandlerInterface[]
     */
    private array $writeHandlers = [];

    private ?FilterEvaluatorInterface $filterEvaluator = null;

    private ?LoggerInterface $logger = null;

    private ?ServerRunnerInterface $serverRunner = null;

    private bool $useSwooleRunner = false;

    /**
     * @var string[]
     */
    private array $saslMechanisms = [];

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

    public function getIdleTimeout(): int
    {
        return $this->idleTimeout;
    }

    public function setIdleTimeout(int $idleTimeout): self
    {
        $this->idleTimeout = $idleTimeout;

        return $this;
    }

    public function isRequireAuthentication(): bool
    {
        return $this->requireAuthentication;
    }

    public function setRequireAuthentication(bool $requireAuthentication): self
    {
        $this->requireAuthentication = $requireAuthentication;

        return $this;
    }

    public function isAllowAnonymous(): bool
    {
        return $this->allowAnonymous;
    }

    public function setAllowAnonymous(bool $allowAnonymous): self
    {
        $this->allowAnonymous = $allowAnonymous;

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

    public function getSslCertKey(): ?string
    {
        return $this->sslCertKey;
    }

    public function setSslCertKey(?string $sslCertKey): self
    {
        $this->sslCertKey = $sslCertKey;

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

    public function getSslCertPassphrase(): ?string
    {
        return $this->sslCertPassphrase;
    }

    public function setSslCertPassphrase(?string $sslCertPassphrase): self
    {
        $this->sslCertPassphrase = $sslCertPassphrase;

        return $this;
    }

    public function getDseAltServer(): ?string
    {
        return $this->dseAltServer;
    }

    public function setDseAltServer(?string $dseAlServer): self
    {
        $this->dseAltServer = $dseAlServer;

        return $this;
    }

    public function getSubschemaEntry(): Dn
    {
        return $this->subschemaEntry ?? new Dn('cn=Subschema');
    }

    public function setSubschemaEntry(Dn $subschemaEntry): self
    {
        $this->subschemaEntry = $subschemaEntry;

        return $this;
    }

    /**
     * @return string[]
     */
    public function getDseNamingContexts(): array
    {
        return $this->dseNamingContexts;
    }

    public function setDseNamingContexts(string ...$dseNamingContexts): self
    {
        $this->dseNamingContexts = $dseNamingContexts;

        return $this;
    }

    public function getDseVendorName(): string
    {
        return $this->dseVendorName;
    }

    public function setDseVendorName(string $dseVendorName): self
    {
        $this->dseVendorName = $dseVendorName;

        return $this;
    }

    public function getDseVendorVersion(): ?string
    {
        return $this->dseVendorVersion;
    }

    public function setDseVendorVersion(?string $dseVendorVersion): self
    {
        $this->dseVendorVersion = $dseVendorVersion;

        return $this;
    }

    public function getBackend(): ?LdapBackendInterface
    {
        return $this->backend;
    }

    public function setBackend(?LdapBackendInterface $backend): self
    {
        $this->backend = $backend;

        return $this;
    }

    public function getPasswordAuthenticator(): ?PasswordAuthenticatableInterface
    {
        return $this->passwordAuthenticator;
    }

    public function setPasswordAuthenticator(?PasswordAuthenticatableInterface $passwordAuthenticator): self
    {
        $this->passwordAuthenticator = $passwordAuthenticator;

        return $this;
    }

    public function getRootDseHandler(): ?RootDseHandlerInterface
    {
        return $this->rootDseHandler;
    }

    public function setRootDseHandler(?RootDseHandlerInterface $rootDseHandler): self
    {
        $this->rootDseHandler = $rootDseHandler;

        return $this;
    }

    /**
     * @return WriteHandlerInterface[]
     */
    public function getWriteHandlers(): array
    {
        return $this->writeHandlers;
    }

    public function addWriteHandler(WriteHandlerInterface $handler): self
    {
        $this->writeHandlers[] = $handler;

        return $this;
    }

    public function getFilterEvaluator(): ?FilterEvaluatorInterface
    {
        return $this->filterEvaluator;
    }

    public function setFilterEvaluator(?FilterEvaluatorInterface $filterEvaluator): self
    {
        $this->filterEvaluator = $filterEvaluator;

        return $this;
    }

    public function getLogger(): ?LoggerInterface
    {
        return $this->logger;
    }

    public function setLogger(?LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    /**
     * @return string[]
     */
    public function getSaslMechanisms(): array
    {
        return $this->saslMechanisms;
    }

    public function setSaslMechanisms(string ...$mechanisms): self
    {
        foreach ($mechanisms as $mechanism) {
            if (!in_array($mechanism, self::SUPPORTED_SASL_MECHANISMS, true)) {
                throw new InvalidArgumentException(sprintf(
                    'The SASL mechanism "%s" is not supported. Supported mechanisms: %s.',
                    $mechanism,
                    implode(', ', self::SUPPORTED_SASL_MECHANISMS)
                ));
            }
        }

        $this->saslMechanisms = array_values($mechanisms);

        return $this;
    }

    public function setServerRunner(ServerRunnerInterface $serverRunner): self
    {
        $this->serverRunner = $serverRunner;

        return $this;
    }

    public function getServerRunner(): ?ServerRunnerInterface
    {
        return $this->serverRunner;
    }

    public function setUseSwooleRunner(bool $use): self
    {
        $this->useSwooleRunner = $use;

        return $this;
    }

    public function getUseSwooleRunner(): bool
    {
        return $this->useSwooleRunner;
    }

    /**
     * @return array{ip: string, port: int, unix_socket: string, transport: string, idle_timeout: int, require_authentication: bool, allow_anonymous: bool, backend: ?LdapBackendInterface, rootdse_handler: ?RootDseHandlerInterface, logger: ?LoggerInterface, use_ssl: bool, ssl_cert: ?string, ssl_cert_key: ?string, ssl_cert_passphrase: ?string, dse_alt_server: ?string, dse_naming_contexts: string[], dse_vendor_name: string, dse_vendor_version: ?string, sasl_mechanisms: string[]}
     */
    public function toArray(): array
    {
        return [
            'ip' => $this->getIp(),
            'port' => $this->getPort(),
            'unix_socket' => $this->getUnixSocket(),
            'transport' => $this->getTransport(),
            'idle_timeout' => $this->getIdleTimeout(),
            'require_authentication' => $this->isRequireAuthentication(),
            'allow_anonymous' => $this->isAllowAnonymous(),
            'backend' => $this->getBackend(),
            'rootdse_handler' => $this->getRootDseHandler(),
            'logger' => $this->getLogger(),
            'use_ssl' => $this->isUseSsl(),
            'ssl_cert' => $this->getSslCert(),
            'ssl_cert_key' => $this->getSslCertKey(),
            'ssl_cert_passphrase' => $this->getSslCertPassphrase(),
            'dse_alt_server' => $this->getDseAltServer(),
            'dse_naming_contexts' => $this->getDseNamingContexts(),
            'dse_vendor_name' => $this->getDseVendorName(),
            'dse_vendor_version' => $this->getDseVendorVersion(),
            'sasl_mechanisms' => $this->getSaslMechanisms(),
        ];
    }
}
