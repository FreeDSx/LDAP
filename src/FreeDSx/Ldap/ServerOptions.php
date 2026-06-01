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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Schema\PasswordPolicySchemaProvider;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\StandardSchemaProvider;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\DefaultPasswordQualityChecker;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\PasswordQualityCheckerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluator;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\SimpleAccessControl;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Configuration\ConfigReloaderInterface;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use Psr\Log\LoggerInterface;
use Closure;

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

    /**
     * Disconnect a client whose response send makes no progress for this many seconds (a stalled reader).
     */
    private int $writeTimeout = 600;

    /**
     * The largest incoming request PDU accepted, in bytes (5 MiB); 0 disables the limit.
     */
    private int $maxRequestSize = 5_242_880;

    private bool $requireAuthentication = true;

    private bool $allowAnonymous = false;

    private bool $useSsl = false;

    private ?string $sslCert = null;

    private ?string $sslCertKey = null;

    private ?string $sslCertPassphrase = null;

    private ?string $dseAltServer = null;

    private ?Dn $subschemaEntry = null;

    private string $dseVendorName = 'FreeDSx';

    private ?string $dseVendorVersion = null;

    private ?WritableLdapBackendInterface $backend = null;

    private ?PasswordAuthenticatableInterface $passwordAuthenticator = null;

    private ?BindNameResolverInterface $identityResolver = null;

    private ?RootDseHandlerInterface $rootDseHandler = null;

    /**
     * @var WriteHandlerInterface[]
     */
    private array $writeHandlers = [];

    private ?FilterEvaluatorInterface $filterEvaluator = null;

    private ?Schema $schema = null;

    private SchemaValidationMode $schemaValidationMode = SchemaValidationMode::Strict;

    private ?AccessControlInterface $accessControl = null;

    private ?AclRules $aclRules = null;

    /**
     * @var list<string>
     */
    private array $privilegedControls = [Control::OID_RELAX_RULES];

    private ?PasswordPolicy $passwordPolicy = null;

    private ?Dn $defaultPasswordPolicyDn = null;

    private PasswordHashScheme $passwordHashScheme = PasswordHashScheme::Bcrypt;

    private ?PasswordQualityCheckerInterface $passwordQualityChecker = null;

    private ?LoggerInterface $logger = null;

    private ?EventLogPolicy $eventLogPolicy = null;

    private ?ServerRunnerInterface $serverRunner = null;

    private bool $useSwooleRunner = false;

    private int $maxConnections = 0;

    private int $maxSearchSize = 1000;

    private int $maxSearchTimeLimit = 120;

    private int $maxSearchPageSize = 1000;

    private ?Closure $onServerReady = null;

    private ?ConfigReloaderInterface $configReloader = null;

    private int $shutdownTimeout = 15;

    private float $socketAcceptTimeout = 0.5;

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

    public function getWriteTimeout(): int
    {
        return $this->writeTimeout;
    }

    public function setWriteTimeout(int $writeTimeout): self
    {
        $this->writeTimeout = $writeTimeout;

        return $this;
    }

    public function getMaxRequestSize(): int
    {
        return $this->maxRequestSize;
    }

    public function setMaxRequestSize(int $maxRequestSize): self
    {
        $this->maxRequestSize = $maxRequestSize;

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

    public function getBackend(): ?WritableLdapBackendInterface
    {
        return $this->backend;
    }

    public function setBackend(?WritableLdapBackendInterface $backend): self
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

    public function getIdentityResolver(): ?BindNameResolverInterface
    {
        return $this->identityResolver;
    }

    public function setIdentityResolver(?BindNameResolverInterface $identityResolver): self
    {
        $this->identityResolver = $identityResolver;

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

    public function getFilterEvaluator(): FilterEvaluatorInterface
    {
        return $this->filterEvaluator ??= new FilterEvaluator($this->getSchema());
    }

    public function setFilterEvaluator(?FilterEvaluatorInterface $filterEvaluator): self
    {
        $this->filterEvaluator = $filterEvaluator;

        return $this;
    }

    public function getSchema(): Schema
    {
        if ($this->schema !== null) {
            return $this->schema;
        }

        $base = StandardSchemaProvider::buildCore();
        $this->schema = $this->isPasswordPolicyEnabled()
            ? $base->merge(PasswordPolicySchemaProvider::build())
            : $base;

        return $this->schema;
    }

    public function setSchema(Schema $schema): self
    {
        $this->schema = $schema;

        return $this;
    }

    public function getSchemaValidationMode(): SchemaValidationMode
    {
        return $this->schemaValidationMode;
    }

    public function setSchemaValidationMode(SchemaValidationMode $mode): self
    {
        $this->schemaValidationMode = $mode;

        return $this;
    }

    public function getAccessControl(): AccessControlInterface
    {
        return $this->accessControl ??= new SimpleAccessControl();
    }

    public function setAccessControl(AccessControlInterface $accessControl): self
    {
        $this->accessControl = $accessControl;

        return $this;
    }

    public function setAclRules(AclRules $aclRules): self
    {
        $this->aclRules = $aclRules;

        return $this;
    }

    public function getAclRules(): AclRules
    {
        return $this->aclRules ??= new AclRules();
    }

    /**
     * Control OIDs treated as privileged on writes: each requires an explicit ControlRule grant (default: Relax Rules).
     *
     * @return list<string>
     */
    public function getPrivilegedControls(): array
    {
        return $this->privilegedControls;
    }

    /**
     * Replace the set of privileged control OIDs. Add e.g. Control::OID_SUBTREE_DELETE to gate Tree-Delete behind a grant.
     */
    public function setPrivilegedControls(string ...$controlOids): self
    {
        $this->privilegedControls = array_values($controlOids);

        return $this;
    }

    /**
     * In-memory fallback policy applied to users that do not resolve a pwdPolicy entry from the DIT.
     */
    public function getPasswordPolicy(): ?PasswordPolicy
    {
        return $this->passwordPolicy;
    }

    public function setPasswordPolicy(?PasswordPolicy $policy): self
    {
        $this->passwordPolicy = $policy;

        return $this;
    }

    /**
     * DN of the default pwdPolicy entry used when a user has no pwdPolicySubentry pointer.
     */
    public function getDefaultPasswordPolicyDn(): ?Dn
    {
        return $this->defaultPasswordPolicyDn;
    }

    public function setDefaultPasswordPolicyDn(?Dn $dn): self
    {
        $this->defaultPasswordPolicyDn = $dn;

        return $this;
    }

    /**
     * Whether any password-policy source is configured.
     */
    public function isPasswordPolicyEnabled(): bool
    {
        return $this->passwordPolicy !== null
            || $this->defaultPasswordPolicyDn !== null;
    }

    /**
     * Output scheme used by the password hasher when writing a new password.
     */
    public function getPasswordHashScheme(): PasswordHashScheme
    {
        return $this->passwordHashScheme;
    }

    public function setPasswordHashScheme(PasswordHashScheme $scheme): self
    {
        $this->passwordHashScheme = $scheme;

        return $this;
    }

    /**
     * Quality check applied to new passwords before they are hashed and stored.
     */
    public function getPasswordQualityChecker(): PasswordQualityCheckerInterface
    {
        return $this->passwordQualityChecker ??= new DefaultPasswordQualityChecker();
    }

    public function setPasswordQualityChecker(PasswordQualityCheckerInterface $checker): self
    {
        $this->passwordQualityChecker = $checker;

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

    public function getEventLogPolicy(): EventLogPolicy
    {
        return $this->eventLogPolicy ??= EventLogPolicy::default();
    }

    public function setEventLogPolicy(EventLogPolicy $policy): self
    {
        $this->eventLogPolicy = $policy;

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
                    implode(', ', self::SUPPORTED_SASL_MECHANISMS),
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

    /**
     * The maximum number of concurrent connections the server will accept.
     *
     * Zero (the default) means no limit.
     */
    public function getMaxConnections(): int
    {
        return $this->maxConnections;
    }

    public function setMaxConnections(int $maxConnections): self
    {
        $this->maxConnections = $maxConnections;

        return $this;
    }

    /**
     * Maximum entries returned per search (default 1000). Zero means no server-side limit.
     */
    public function getMaxSearchSize(): int
    {
        return $this->maxSearchSize;
    }

    public function setMaxSearchSize(int $maxSearchSize): self
    {
        $this->maxSearchSize = $maxSearchSize;

        return $this;
    }

    /**
     * Maximum seconds a search may run (default 120). Zero means no server-side limit.
     */
    public function getMaxSearchTimeLimit(): int
    {
        return $this->maxSearchTimeLimit;
    }

    public function setMaxSearchTimeLimit(int $maxSearchTimeLimit): self
    {
        $this->maxSearchTimeLimit = $maxSearchTimeLimit;

        return $this;
    }

    /**
     * Maximum entries per paged-search page (default 1000). Zero means no server-side limit.
     */
    public function getMaxSearchPageSize(): int
    {
        return $this->maxSearchPageSize;
    }

    public function setMaxSearchPageSize(int $maxSearchPageSize): self
    {
        $this->maxSearchPageSize = $maxSearchPageSize;

        return $this;
    }

    public function makeSearchLimits(): SearchLimits
    {
        return new SearchLimits(
            maxSearchSize: $this->maxSearchSize,
            maxSearchTimeLimit: $this->maxSearchTimeLimit,
            maxSearchPageSize: $this->maxSearchPageSize,
        );
    }

    /**
     * Seconds to wait for active connections to close gracefully before forcing them closed on shutdown.
     */
    public function getShutdownTimeout(): int
    {
        return $this->shutdownTimeout;
    }

    public function setShutdownTimeout(int $shutdownTimeout): self
    {
        $this->shutdownTimeout = $shutdownTimeout;

        return $this;
    }

    /**
     * Seconds (fractional) to wait for a new client connection before re-checking server state.
     */
    public function getSocketAcceptTimeout(): float
    {
        return $this->socketAcceptTimeout;
    }

    public function setSocketAcceptTimeout(float $socketAcceptTimeout): self
    {
        $this->socketAcceptTimeout = $socketAcceptTimeout;

        return $this;
    }

    public function getUseSwooleRunner(): bool
    {
        return $this->useSwooleRunner;
    }

    public function getOnServerReady(): ?Closure
    {
        return $this->onServerReady;
    }

    public function setOnServerReady(?Closure $onServerReady): self
    {
        $this->onServerReady = $onServerReady;

        return $this;
    }

    public function getConfigReloader(): ?ConfigReloaderInterface
    {
        return $this->configReloader;
    }

    public function setConfigReloader(?ConfigReloaderInterface $configReloader): self
    {
        $this->configReloader = $configReloader;

        return $this;
    }

    /**
     * @return array{ip: string, port: int, unix_socket: string, transport: string, idle_timeout: int, require_authentication: bool, allow_anonymous: bool, backend: ?WritableLdapBackendInterface, rootdse_handler: ?RootDseHandlerInterface, logger: ?LoggerInterface, use_ssl: bool, ssl_cert: ?string, ssl_cert_key: ?string, ssl_cert_passphrase: ?string, dse_alt_server: ?string, dse_vendor_name: string, dse_vendor_version: ?string, sasl_mechanisms: string[]}
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
            'dse_vendor_name' => $this->getDseVendorName(),
            'dse_vendor_version' => $this->getDseVendorVersion(),
            'sasl_mechanisms' => $this->getSaslMechanisms(),
        ];
    }
}
