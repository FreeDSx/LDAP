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
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Schema\PasswordPolicySchemaProvider;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\StandardSchemaProvider;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Sasl\External\ExternalCredentialMapperInterface;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\DefaultPasswordQualityChecker;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\PasswordQualityCheckerInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Config\StorageConfigInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\Configuration\ConfigReloaderInterface;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitRules;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\TlsVersion;
use Psr\Log\LoggerInterface;
use Closure;

/**
 * @api
 */
final class ServerOptions
{
    public const SASL_PLAIN = 'PLAIN';

    public const SASL_CRAM_MD5 = 'CRAM-MD5';

    public const SASL_DIGEST_MD5 = 'DIGEST-MD5';

    public const SASL_EXTERNAL = 'EXTERNAL';

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
        self::SASL_EXTERNAL,
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

    private TlsVersion $minTlsVersion = TlsVersion::Tls1_2;

    private string $sslCiphers = 'DEFAULT';

    private bool $sslValidateCert = false;

    private ?bool $sslAllowSelfSigned = null;

    private ?string $sslCaCert = null;

    private ?string $dseAltServer = null;

    private ?Dn $subschemaEntry = null;

    private string $dseVendorName = 'FreeDSx';

    private ?string $dseVendorVersion = null;

    private StorageConfigInterface $storageConfig;

    private ?PasswordAuthenticatableInterface $passwordAuthenticator = null;

    private ?ManagerIdentity $manager = null;

    private ?SubjectMatcherInterface $administrators = null;

    private ?BindNameResolverInterface $identityResolver = null;

    private ?ExternalCredentialMapperInterface $externalCredentialMapper = null;

    private ?Schema $schema = null;

    private SchemaValidationMode $schemaValidationMode = SchemaValidationMode::Strict;

    private ?AccessControlInterface $accessControl = null;

    private ?AclRules $aclRules = null;

    /**
     * Memoized secure default, rebuilt when the administrator subject changes so it never goes stale.
     */
    private ?AccessControlInterface $defaultAccessControl = null;

    private ?AclRules $defaultAclRules = null;

    /**
     * @var list<string>
     */
    private array $privilegedControls = [
        Control::OID_RELAX_RULES,
        Control::OID_SYNC_REQUEST,
    ];

    /**
     * @var list<string>
     */
    private array $privilegedExtendedOps = [
        ExtendedRequest::OID_PPOLICY_STATE_FORWARD,
    ];

    private ?PasswordPolicy $passwordPolicy = null;

    private ?Dn $defaultPasswordPolicyDn = null;

    private PasswordHashScheme $passwordHashScheme = PasswordHashScheme::Bcrypt;

    private ?PasswordQualityCheckerInterface $passwordQualityChecker = null;

    private ?LoggerInterface $logger = null;

    private ?EventLogPolicy $eventLogPolicy = null;

    private ?ServerRunnerInterface $serverRunner = null;

    private RunnerMode $runner = RunnerMode::Pcntl;

    private bool $monitorEnabled = false;

    private bool $syncEnabled = false;

    private ?ChangeJournalConfig $changeJournalConfig = null;

    private ?ReplicaConfig $replicaConfig = null;

    private ?string $monitorSnapshotPath = null;

    private ?MetricsRecorderInterface $metricsRecorder = null;

    private int $maxConnections = 0;

    private int $maxSearchSize = 1000;

    private int $maxSearchTimeLimit = 120;

    private int $maxSearchPageSize = 1000;

    private int $maxSearchLookthrough = 5000;

    private int $maxSearchPagedLookthrough = 0;

    private ?SearchLimitRules $searchLimitRules = null;

    private ?Closure $onServerReady = null;

    private ?ConfigReloaderInterface $configReloader = null;

    private int $shutdownTimeout = 15;

    private float $socketAcceptTimeout = 0.5;

    /**
     * @var string[]
     */
    private array $saslMechanisms = [];

    /**
     * @param ?StorageConfigInterface $storageConfig Storage backend; a transient in-memory directory when omitted.
     */
    public function __construct(?StorageConfigInterface $storageConfig = null)
    {
        $this->storageConfig = $storageConfig ?? InMemoryStorageConfig::withEntries();
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

    public function getStorageConfig(): StorageConfigInterface
    {
        return $this->storageConfig;
    }

    public function setStorageConfig(StorageConfigInterface $storageConfig): self
    {
        $this->storageConfig = $storageConfig;

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

    public function getManager(): ?ManagerIdentity
    {
        return $this->manager;
    }

    /**
     * The config-resident manager super-user (break-glass): bypasses access control and password-policy lockout.
     */
    public function setManager(?ManagerIdentity $manager): self
    {
        $this->manager = $manager;

        return $this;
    }

    public function getAdministrators(): ?SubjectMatcherInterface
    {
        return $this->administrators;
    }

    /**
     * The directory-resident administrator subject (a DN or group) granted password-reset and privileged-op rights.
     */
    public function setAdministrators(?SubjectMatcherInterface $administrators): self
    {
        $this->administrators = $administrators;
        // Drop any memoized secure default so it is rebuilt with the new administrator instead of a stale one.
        $this->defaultAclRules = null;
        $this->defaultAccessControl = null;

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

    public function getExternalCredentialMapper(): ?ExternalCredentialMapperInterface
    {
        return $this->externalCredentialMapper;
    }

    /**
     * Custom cert->identity policy for SASL EXTERNAL (e.g. map a SAN/UPN or rewrite the DN); null uses the subject DN.
     */
    public function setExternalCredentialMapper(?ExternalCredentialMapperInterface $externalCredentialMapper): self
    {
        $this->externalCredentialMapper = $externalCredentialMapper;

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
        return $this->accessControl ?? ($this->defaultAccessControl ??= new RuleBasedAccessControl(
            $this->getAclRules(),
        ));
    }

    public function setAccessControl(AccessControlInterface $accessControl): self
    {
        $this->accessControl = $accessControl;

        return $this;
    }

    public function setAclRules(AclRules $aclRules): self
    {
        $this->aclRules = $aclRules;
        // Drop any access control derived from the previous rules so it is rebuilt from these.
        $this->defaultAccessControl = null;

        return $this;
    }

    public function getAclRules(): AclRules
    {
        return $this->aclRules ?? ($this->defaultAclRules ??= AclRules::secureDefault($this->administrators));
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
     * Extended operation OIDs that require an explicit ExtendedOperationRule grant (deny-by-default).
     *
     * @return list<string>
     */
    public function getPrivilegedExtendedOps(): array
    {
        return $this->privilegedExtendedOps;
    }

    /**
     * @param list<string> $oids
     */
    public function setPrivilegedExtendedOps(array $oids): self
    {
        $this->privilegedExtendedOps = array_values($oids);

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

    public function setRunner(RunnerMode $runner): self
    {
        $this->runner = $runner;

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

    public function isMonitorEnabled(): bool
    {
        return $this->monitorEnabled;
    }

    public function setMonitorEnabled(bool $monitorEnabled): self
    {
        $this->monitorEnabled = $monitorEnabled;

        return $this;
    }

    public function isSyncEnabled(): bool
    {
        return $this->syncEnabled;
    }

    public function setSyncEnabled(bool $syncEnabled): self
    {
        $this->syncEnabled = $syncEnabled;

        return $this;
    }

    public function getChangeJournalConfig(): ChangeJournalConfig
    {
        return $this->changeJournalConfig ??= new ChangeJournalConfig();
    }

    public function setChangeJournalConfig(ChangeJournalConfig $changeJournalConfig): self
    {
        $this->changeJournalConfig = $changeJournalConfig;

        return $this;
    }

    /**
     * Named constructor for a read-only replica that mirrors an upstream primary over RFC 4533.
     *
     * @param StorageConfigInterface $storageConfig Persistent storage for the replica.
     */
    public static function forReplica(
        ReplicaConfig $replicaConfig,
        StorageConfigInterface $storageConfig,
    ): self {
        return (new self($storageConfig))->setReplicaConfig($replicaConfig);
    }

    public function getReplicaConfig(): ?ReplicaConfig
    {
        return $this->replicaConfig;
    }

    public function setReplicaConfig(ReplicaConfig $replicaConfig): self
    {
        $this->replicaConfig = $replicaConfig;

        return $this;
    }

    /**
     * Whether this server is a read-only replica, derived from having a replica config.
     */
    public function isReadOnly(): bool
    {
        return $this->replicaConfig !== null;
    }

    /**
     * The configured cn=monitor snapshot path, or a per-port default under the system temp directory.
     */
    public function getMonitorSnapshotPath(): string
    {
        return $this->monitorSnapshotPath
            ?? sys_get_temp_dir() . '/freedsx_ldap_monitor_' . $this->port . '.json';
    }

    public function setMonitorSnapshotPath(?string $monitorSnapshotPath): self
    {
        $this->monitorSnapshotPath = $monitorSnapshotPath;

        return $this;
    }

    public function getMetricsRecorder(): MetricsRecorderInterface
    {
        return $this->metricsRecorder ??= new NullMetricsRecorder();
    }

    public function setMetricsRecorder(MetricsRecorderInterface $metricsRecorder): self
    {
        $this->metricsRecorder = $metricsRecorder;

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

    /**
     * Maximum entries examined per search before adminLimitExceeded (default 5000). Guards unindexed scans. Zero disables.
     */
    public function getMaxSearchLookthrough(): int
    {
        return $this->maxSearchLookthrough;
    }

    public function setMaxSearchLookthrough(int $maxSearchLookthrough): self
    {
        $this->maxSearchLookthrough = $maxSearchLookthrough;

        return $this;
    }

    /**
     * Lookthrough cap for paged searches.
     *
     * A zero value falls back to the regular lookthrough.
     */
    public function getMaxSearchPagedLookthrough(): int
    {
        return $this->maxSearchPagedLookthrough;
    }

    public function setMaxSearchPagedLookthrough(int $maxSearchPagedLookthrough): self
    {
        $this->maxSearchPagedLookthrough = $maxSearchPagedLookthrough;

        return $this;
    }

    public function setSearchLimitRules(SearchLimitRules $searchLimitRules): self
    {
        $this->searchLimitRules = $searchLimitRules;

        return $this;
    }

    public function getSearchLimitRules(): SearchLimitRules
    {
        return $this->searchLimitRules ??= new SearchLimitRules();
    }

    public function makeSearchLimits(): SearchLimits
    {
        return new SearchLimits(
            maxSearchSize: $this->maxSearchSize,
            maxSearchTimeLimit: $this->maxSearchTimeLimit,
            maxSearchPageSize: $this->maxSearchPageSize,
            maxSearchLookthrough: $this->maxSearchLookthrough,
            maxSearchPagedLookthrough: $this->maxSearchPagedLookthrough,
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

    public function getRunner(): RunnerMode
    {
        return $this->runner;
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
     * @return array{ip: string, port: int, unix_socket: string, transport: string, idle_timeout: int, require_authentication: bool, allow_anonymous: bool, logger: ?LoggerInterface, use_ssl: bool, ssl_cert: ?string, ssl_cert_key: ?string, ssl_cert_passphrase: ?string, min_tls_version: string, ssl_ciphers: string, ssl_validate_cert: bool, ssl_allow_self_signed: ?bool, ssl_ca_cert: ?string, monitor_enabled: bool, monitor_snapshot_path: ?string, dse_alt_server: ?string, dse_vendor_name: string, dse_vendor_version: ?string, sasl_mechanisms: string[]}
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
            'logger' => $this->getLogger(),
            'use_ssl' => $this->isUseSsl(),
            'ssl_cert' => $this->getSslCert(),
            'ssl_cert_key' => $this->getSslCertKey(),
            'ssl_cert_passphrase' => $this->getSslCertPassphrase(),
            'min_tls_version' => $this->getMinTlsVersion()->value,
            'ssl_ciphers' => $this->getSslCiphers(),
            'ssl_validate_cert' => $this->isSslValidateCert(),
            'ssl_allow_self_signed' => $this->getSslAllowSelfSigned(),
            'ssl_ca_cert' => $this->getSslCaCert(),
            'monitor_enabled' => $this->isMonitorEnabled(),
            'monitor_snapshot_path' => $this->monitorSnapshotPath,
            'dse_alt_server' => $this->getDseAltServer(),
            'dse_vendor_name' => $this->getDseVendorName(),
            'dse_vendor_version' => $this->getDseVendorVersion(),
            'sasl_mechanisms' => $this->getSaslMechanisms(),
        ];
    }
}
