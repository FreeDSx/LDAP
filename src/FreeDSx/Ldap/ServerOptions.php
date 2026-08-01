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
use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Sasl\External\ExternalCredentialMapperInterface;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\DefaultPasswordQualityChecker;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\PasswordQualityCheckerInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Config\StorageConfigInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\Config\SchemaConfig;
use FreeDSx\Ldap\Server\Configuration\ConfigReloaderInterface;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitRules;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;

/**
 * @api
 */
final class ServerOptions implements ServerListenerOptionsInterface
{
    use ServerListenerOptionsTrait;

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

    private ?string $dseAltServer = null;

    private string $dseVendorName = 'FreeDSx';

    private ?string $dseVendorVersion = null;

    private StorageConfigInterface $storageConfig;

    private ?PasswordAuthenticatableInterface $passwordAuthenticator = null;

    private ?ManagerIdentity $manager = null;

    private ?SubjectMatcherInterface $administrators = null;

    private ?BindNameResolverInterface $identityResolver = null;

    private ?ExternalCredentialMapperInterface $externalCredentialMapper = null;

    private SchemaConfig $schemaConfig;

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

    private ?ServerRunnerInterface $serverRunner = null;

    private bool $syncEnabled = false;

    private ?ChangeJournalConfig $changeJournalConfig = null;

    private ?ReplicaConfig $replicaConfig = null;

    private int $maxSearchSize = 1000;

    private int $maxSearchTimeLimit = 120;

    private int $maxSearchPageSize = 1000;

    private int $maxSearchLookthrough = 5000;

    private int $maxSearchPagedLookthrough = 0;

    private ?SearchLimitRules $searchLimitRules = null;

    private ?ConfigReloaderInterface $configReloader = null;

    /**
     * @var string[]
     */
    private array $saslMechanisms = [];

    /**
     * @param ?StorageConfigInterface $storageConfig Storage backend; a transient in-memory directory when omitted.
     * @param ?NetworkConfig $networkConfig Listener and TLS settings; defaults to a plaintext listener on 0.0.0.0:389.
     * @param ?SchemaConfig $schemaConfig Schema sources and validation; defaults to the schemas this package ships.
     */
    public function __construct(
        ?StorageConfigInterface $storageConfig = null,
        ?NetworkConfig $networkConfig = null,
        ?RunnerConfig $runnerConfig = null,
        ?SchemaConfig $schemaConfig = null,
    ) {
        $this->storageConfig = $storageConfig ?? InMemoryStorageConfig::withEntries();
        $this->networkConfig = $networkConfig ?? new NetworkConfig();
        $this->runnerConfig = $runnerConfig ?? new RunnerConfig();
        $this->schemaConfig = $schemaConfig ?? new SchemaConfig();
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
        return $this->schemaConfig->getSubschemaEntry();
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

    public function getSchemaConfig(): SchemaConfig
    {
        return $this->schemaConfig;
    }

    public function setSchemaConfig(SchemaConfig $schemaConfig): self
    {
        $this->schemaConfig = $schemaConfig;

        return $this;
    }

    /**
     * The schema every configured source resolves to; read once and reused.
     *
     * @throws SchemaParseException
     */
    public function getSchema(): Schema
    {
        return $this->schemaConfig->resolve();
    }

    public function getSchemaValidationMode(): SchemaValidationMode
    {
        return $this->schemaConfig->getValidationMode();
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
     * @param PdoConfig $storageConfig Persistent storage for the replica; PDO is required.
     */
    public static function forReplica(
        ReplicaConfig $replicaConfig,
        PdoConfig $storageConfig,
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

    public function getConfigReloader(): ?ConfigReloaderInterface
    {
        return $this->configReloader;
    }

    public function setConfigReloader(?ConfigReloaderInterface $configReloader): self
    {
        $this->configReloader = $configReloader;

        return $this;
    }
}
