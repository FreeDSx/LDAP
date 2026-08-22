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
use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Sasl\External\ExternalCredentialMapperInterface;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\PasswordConfig;
use FreeDSx\Ldap\Server\Config\Replication\ConsumerConfig;
use FreeDSx\Ldap\Server\Config\ReplicationConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\Config\SchemaConfig;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
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

    private ?AccessControlInterface $accessControl = null;

    private ?AclRules $aclRules = null;

    /**
     * Memoized secure default, rebuilt when the administrator subject changes so it never goes stale.
     */
    private ?AccessControlInterface $defaultAccessControl = null;

    private ?AclRules $defaultAclRules = null;

    private ?ServerRunnerInterface $serverRunner = null;

    private ?ChangeJournalConfig $changeJournalConfig = null;

    private int $maxSearchSize = 1000;

    private int $maxSearchTimeLimit = 120;

    private int $maxSearchPageSize = 1000;

    private int $maxSearchLookthrough = 5000;

    private int $maxSearchPagedLookthrough = 0;

    private int $maxPagingSessions = 25;

    private ?SearchLimitRules $searchLimitRules = null;

    private ?ConfigReloaderInterface $configReloader = null;

    /**
     * @var string[]
     */
    private array $saslMechanisms = [];

    /**
     * @param StorageConfigInterface $storageConfig Where the directory lives.
     * @param NetworkConfig $networkConfig Listener and TLS settings; defaults to a plaintext listener on 0.0.0.0:389.
     * @param SchemaConfig $schemaConfig Schema sources and validation; defaults to the schemas this package ships.
     * @param ReplicationConfig $replicationConfig Replication role; defaults to playing none.
     * @param PasswordConfig $passwordConfig How passwords are governed and stored; defaults to enforcing no policy.
     */
    public function __construct(
        StorageConfigInterface $storageConfig,
        private NetworkConfig $networkConfig = new NetworkConfig(),
        private RunnerConfig $runnerConfig = new RunnerConfig(),
        private SchemaConfig $schemaConfig = new SchemaConfig(),
        private ReplicationConfig $replicationConfig = new ReplicationConfig(),
        private PasswordConfig $passwordConfig = new PasswordConfig(),
    ) {
        $this->storageConfig = $storageConfig;
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
        // The subschema rule is applied here rather than in secureDefault(), since only this side knows the DN.
        return $this->aclRules ?? ($this->defaultAclRules ??= AclRules::secureDefault($this->administrators)
            ->withSubschemaAccess(
                Subject::authenticated(),
                $this->getSubschemaEntry(),
            ));
    }

    public function getPasswordConfig(): PasswordConfig
    {
        return $this->passwordConfig;
    }

    public function setPasswordConfig(PasswordConfig $passwordConfig): self
    {
        $this->passwordConfig = $passwordConfig;

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

    /**
     * The journal settings for recording changes, or null when nothing is recorded.
     *
     * A configured provider records regardless, since it streams from the journal.
     */
    public function getChangeJournalConfig(): ?ChangeJournalConfig
    {
        if ($this->changeJournalConfig !== null) {
            return $this->changeJournalConfig;
        }

        return $this->getReplicationConfig()->isProvider()
            ? $this->changeJournalConfig = new ChangeJournalConfig()
            : null;
    }

    public function setChangeJournalConfig(ChangeJournalConfig $changeJournalConfig): self
    {
        $this->changeJournalConfig = $changeJournalConfig;

        return $this;
    }

    /**
     * A server playing no replication role holds one with both roles empty.
     */
    public function getReplicationConfig(): ReplicationConfig
    {
        return $this->replicationConfig;
    }

    public function setReplicationConfig(ReplicationConfig $replicationConfig): self
    {
        $this->replicationConfig = $replicationConfig;

        return $this;
    }

    /**
     * The upstream this server mirrors, or null when it mirrors nothing.
     */
    public function getConsumerConfig(): ?ConsumerConfig
    {
        return $this->getReplicationConfig()
            ->getConsumer();
    }

    /**
     * Whether this server refuses client writes, which today follows from mirroring an upstream.
     */
    public function isReadOnly(): bool
    {
        return $this->getConsumerConfig() !== null;
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

    /**
     * Paged searches a connection may leave unfinished before the least recent is discarded. Zero means no cap.
     */
    public function getMaxPagingSessions(): int
    {
        return $this->maxPagingSessions;
    }

    public function setMaxPagingSessions(int $maxPagingSessions): self
    {
        $this->maxPagingSessions = $maxPagingSessions;

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
            maxPagingSessions: $this->maxPagingSessions,
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
