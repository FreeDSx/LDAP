<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Ldif\Output\FileLdifOutput;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ExtendedOperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitRule;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitRules;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\JsonStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use FreeDSx\Ldap\Server\Config\ConfidentialityRequirement;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\Replication\ProviderConfig;
use FreeDSx\Ldap\Server\Config\ReplicationConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\FileFlagConfigReloader;
use PDO;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

use function Swoole\Coroutine\run;

final class LdapServerCommand extends Command
{
    use ConsoleOptionsTrait;

    public const MANAGER_DN = 'cn=manager';

    public const MANAGER_PASSWORD = 'manager-pass';

    /**
     * Tests assert on replicated state, so they should not wait a production poll for it.
     */
    private const SYNC_POLL_INTERVAL = 0.05;

    /**
     * Writes are denied by default, so tests that write bind as this identity.
     */
    private const ADMIN_DN = 'cn=admin,dc=foo,dc=bar';

    private const SEED_LDIF = __DIR__ . '/../resources/seed/server-seed.ldif';

    private const SASL_SEED_LDIF = __DIR__ . '/../resources/seed/server-sasl-seed.ldif';

    private const SSL_KEY = __DIR__ . '/../resources/cert/slapd.key';

    private const SSL_CERT = __DIR__ . '/../resources/cert/slapd.crt';

    private const EXTERNAL_CA_CERT = __DIR__ . '/../resources/cert/test-cases/ext-ca.crt';

    private const VALID_STORAGE = ['memory', 'json', 'sqlite', 'mysql'];

    protected function configure(): void
    {
        $this
            ->setName('ldap-server')
            ->setDescription('Run the test LDAP server')
            ->addOption(
                'transport',
                null,
                InputOption::VALUE_REQUIRED,
                'Transport type (tcp, ssl, unix)',
                'tcp',
            )
            ->addOption(
                'port',
                null,
                InputOption::VALUE_REQUIRED,
                'Port to listen on',
                (string) TestWorker::port(),
            )
            ->addOption(
                'runner',
                null,
                InputOption::VALUE_REQUIRED,
                'Server runner (pcntl, swoole)',
                'pcntl',
            )
            ->addOption(
                'storage',
                null,
                InputOption::VALUE_REQUIRED,
                'Storage adapter (' . implode(', ', self::VALID_STORAGE) . ')',
                'memory',
            )
            ->addOption(
                'entries',
                null,
                InputOption::VALUE_REQUIRED,
                'Number of extra entries to seed (used to test paging)',
                '0',
            )
            ->addOption(
                'max-search-lookthrough',
                null,
                InputOption::VALUE_REQUIRED,
                'Maximum entries examined per search before adminLimitExceeded (0 = no limit)',
                '5000',
            )
            ->addOption(
                'max-search-paged-lookthrough',
                null,
                InputOption::VALUE_REQUIRED,
                'Lookthrough cap for paged searches (0 = fall back to the regular lookthrough)',
                '0',
            )
            ->addOption(
                'max-paging-sessions',
                null,
                InputOption::VALUE_REQUIRED,
                'Unfinished paged searches a connection may hold before the least recent is discarded (0 = no cap)',
                '25',
            )
            ->addOption(
                'authenticated-lookthrough',
                null,
                InputOption::VALUE_REQUIRED,
                'When > 0, a per-identity rule giving authenticated identities this lookthrough',
                '0',
            )
            ->addOption(
                'sasl',
                null,
                InputOption::VALUE_NONE,
                'Enable SASL mechanisms with plaintext-password storage',
            )
            ->addOption(
                'allow-anonymous',
                null,
                InputOption::VALUE_NONE,
                'Allow anonymous bind',
            )
            ->addOption(
                'require-confidentiality',
                null,
                InputOption::VALUE_REQUIRED,
                'Refuse unprotected connections: none, bind (credential-bearing binds), or all (every operation)',
                'none',
            )
            ->addOption(
                'external',
                null,
                InputOption::VALUE_NONE,
                'Enable SASL EXTERNAL with client-certificate validation (implies TLS)',
            )
            ->addOption(
                'external-allow-proxy',
                null,
                InputOption::VALUE_NONE,
                'Grant the EXTERNAL cert identity (cn=extuser) the Proxied Authorization control over dc=foo,dc=bar',
            )
            ->addOption(
                'allow-sync',
                null,
                InputOption::VALUE_NONE,
                'Grant authenticated identities the (privileged) content-sync control over dc=foo,dc=bar',
            )
            ->addOption(
                'allow-ppolicy-forward',
                null,
                InputOption::VALUE_NONE,
                'Enable password policy with lockout and grant cn=user the privileged ppolicy-state forward extended op',
            )
            ->addOption(
                'manager',
                null,
                InputOption::VALUE_NONE,
                'Configure a break-glass manager identity (cn=manager) so tests can reset passwords',
            )
            ->addOption(
                'seed',
                null,
                InputOption::VALUE_REQUIRED,
                'Load directory data from an LDIF file via LdapServer::seed() instead of the built-in entries',
                '',
            )
            ->addOption(
                'changes',
                null,
                InputOption::VALUE_REQUIRED,
                'After seeding, replay an LDIF changelog file via LdapServer::applyChanges()',
                '',
            )
            ->addOption(
                'dump',
                null,
                InputOption::VALUE_REQUIRED,
                'After seeding/applying changes, dump the directory to an LDIF file via LdapServer::dump()',
                '',
            )
            ->addOption(
                'reload-flag-file',
                null,
                InputOption::VALUE_REQUIRED,
                'On SIGHUP, re-read this file and enable anonymous bind when it contains "allow-anonymous"',
                '',
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        $io = new SymfonyStyle($input, $output);
        $transport = $this->getStringOption($input, 'transport');
        $port = (int) $this->getStringOption($input, 'port');
        $storageType = $this->getStringOption($input, 'storage');
        $runner = $this->getStringOption($input, 'runner');
        $entryCount = (int) $this->getStringOption($input, 'entries');
        $sasl = $input->getOption('sasl') === true;
        $external = $input->getOption('external') === true;
        $allowAnonymous = $input->getOption('allow-anonymous') === true;
        $seedFile = $this->getStringOption($input, 'seed');
        $changesFile = $this->getStringOption($input, 'changes');
        $dumpFile = $this->getStringOption($input, 'dump');
        $reloadFlagFile = $this->getStringOption($input, 'reload-flag-file');
        $useSsl = false;

        if (!in_array($storageType, self::VALID_STORAGE, true)) {
            $io->error("Invalid --storage value: {$storageType}. Expected one of: " . implode(', ', self::VALID_STORAGE) . '.');

            return Command::FAILURE;
        }

        if (!in_array($runner, ['pcntl', 'swoole'], true)) {
            $io->error("Invalid --runner value: {$runner}. Expected one of: pcntl, swoole.");

            return Command::FAILURE;
        }

        if ($transport === 'ssl') {
            $transport = 'tcp';
            $useSsl = true;
        }

        $confidentiality = match ($this->getStringOption($input, 'require-confidentiality')) {
            'bind' => ConfidentialityRequirement::CredentialBind,
            'all' => ConfidentialityRequirement::AllOperations,
            default => ConfidentialityRequirement::None,
        };

        $entries = [];

        if ($external) {
            // Subject "/DC=bar/DC=foo/CN=extuser" maps (reversed) to this DN via SubjectDnCredentialMapper.
            $entries[] = Entry::fromArray(
                'cn=extuser,dc=foo,dc=bar',
                [
                    'cn' => 'extuser',
                    'objectClass' => 'inetOrgPerson',
                    'sn' => 'External',
                ],
            );
        }

        for ($i = 1; $i <= $entryCount; $i++) {
            $entries[] = Entry::fromArray(
                "cn=entry-{$i},dc=foo,dc=bar",
                [
                    'cn' => "entry-{$i}",
                    'objectClass' => 'inetOrgPerson',
                    'sn' => 'Entry',
                    // Must be a type the schema defines, or every assertion on it is Undefined (RFC 4511 4.5.1.7).
                    'employeeNumber' => (string) $i,
                ],
            );
        }

        $network = (new NetworkConfig())
            ->setPort($port)
            ->setTransport($transport)
            ->setUnixSocket(TestWorker::path('ldap.socket'))
            ->setSslCert(self::SSL_CERT)
            ->setSslCertKey(self::SSL_KEY)
            ->setUseSsl($useSsl)
            ->setSocketAcceptTimeout(0.1)
            ->setShutdownTimeout(0);

        $options = (new ServerOptions($this->createStorageConfig($storageType), $network))
            ->setRunnerConfig(new RunnerConfig($runner === 'swoole' ? RunnerMode::Swoole : RunnerMode::Pcntl))
            ->setAllowAnonymous($allowAnonymous)
            ->setRequireConfidentiality($confidentiality)
            ->setAdministrators(Subject::dn(self::ADMIN_DN))
            ->setMaxSearchLookthrough((int) $this->getStringOption($input, 'max-search-lookthrough'))
            ->setMaxSearchPagedLookthrough((int) $this->getStringOption($input, 'max-search-paged-lookthrough'))
            ->setMaxPagingSessions((int) $this->getStringOption($input, 'max-paging-sessions'))
            ->setReplicationConfig(ReplicationConfig::forProvider(
                (new ProviderConfig())->setPollInterval(self::SYNC_POLL_INTERVAL),
            ))
            ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL));

        $authenticatedLookthrough = (int) $this->getStringOption($input, 'authenticated-lookthrough');
        if ($authenticatedLookthrough > 0) {
            $rules = (new SearchLimitRules())->withRules(
                SearchLimitRule::for(
                    Subject::authenticated(),
                    new SearchLimits(maxSearchLookthrough: $authenticatedLookthrough),
                ),
            );
            $options->setSearchLimitRules($rules);
        }

        if ($reloadFlagFile !== '') {
            $options->setConfigReloader(new FileFlagConfigReloader($reloadFlagFile));
        }

        $container = Container::forServer($options);
        $server = new LdapServer(
            $options,
            $container,
        );
        // Raw import (no schema validation) so tests can seed synthetic fixtures such as the paging `foo` attribute.
        $storage = $container->get(EntryStorageInterface::class);

        if ($sasl) {
            $options->setSaslMechanisms(
                ServerOptions::SASL_PLAIN,
                ServerOptions::SASL_CRAM_MD5,
                ServerOptions::SASL_SCRAM_SHA_256,
            );
        }

        if ($external) {
            $options->getNetworkConfig()
                ->setSslValidateCert(true)
                ->setSslCaCert(self::EXTERNAL_CA_CERT);
            $options->setSaslMechanisms(ServerOptions::SASL_EXTERNAL);
        }

        if ($external && $input->getOption('external-allow-proxy') === true) {
            $options->setAclRules(
                $options->getAclRules()->appendControlRules(ControlRule::allow(
                    Subject::dn('cn=extuser,dc=foo,dc=bar'),
                    Target::subtree('dc=foo,dc=bar'),
                    Control::OID_PROXY_AUTHORIZATION,
                )),
            );
        }

        if ($input->getOption('allow-sync') === true) {
            $options->setAclRules(
                $options->getAclRules()->appendControlRules(ControlRule::allow(
                    Subject::dn('cn=user,dc=foo,dc=bar'),
                    Target::subtree('dc=foo,dc=bar'),
                    Control::OID_SYNC_REQUEST,
                )),
            );
        }

        if ($input->getOption('allow-ppolicy-forward') === true) {
            $options
                ->setPasswordPolicy(new PasswordPolicy(
                    lockout: new PasswordLockoutRules(
                        enabled: true,
                        maxFailure: 2,
                    ),
                ))
                ->setAclRules(
                    $options->getAclRules()
                        ->appendExtendedOperationRules(
                            ExtendedOperationRule::allow(
                                Subject::dn('cn=user,dc=foo,dc=bar'),
                                ExtendedRequest::OID_PPOLICY_STATE_FORWARD,
                            ),
                        )
                        // Matches the base the replica syncs, so the forward reaches exactly what it replicates.
                        ->appendAttributeRules(
                            AttributeRule::allow(
                                Subject::dn('cn=user,dc=foo,dc=bar'),
                                Target::subtree('dc=foo,dc=bar'),
                                PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
                                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                                PasswordPolicyOid::NAME_PWD_LAST_SUCCESS,
                            )->forWrite(),
                        ),
                );
        }

        if ($input->getOption('manager') === true) {
            $options->setManager(new ManagerIdentity(
                new Dn(self::MANAGER_DN),
                '{SHA}' . base64_encode(sha1(self::MANAGER_PASSWORD, true)),
            ));
        }

        $fixedSeed = $sasl
            ? self::SASL_SEED_LDIF
            : self::SEED_LDIF;

        $loadData = function () use ($server, $storage, $seedFile, $fixedSeed, $entries, $changesFile, $dumpFile): void {
            $server->seed(new FileLdifLoader($seedFile !== '' ? $seedFile : $fixedSeed));

            // The generated and cert-mapped entries stay a raw import, since they carry synthetic attributes.
            if ($entries !== []) {
                (new LdapImporter($storage))->importEntries($entries);
            }

            if ($changesFile !== '') {
                $server->applyChanges(new FileLdifLoader($changesFile));
            }

            if ($dumpFile !== '') {
                $server->dump(new FileLdifOutput($dumpFile));
            }
        };

        if ($runner === 'swoole') {
            run($loadData);
        } else {
            $loadData();
        }

        $server->run();

        return Command::SUCCESS;
    }

    private function createStorageConfig(string $storageType): StorageConfigInterface
    {
        if ($storageType === 'json') {
            $filePath = TestWorker::path('server.json');

            if (file_exists($filePath)) {
                unlink($filePath);
            }

            return JsonStorageConfig::forFile($filePath);
        }

        if ($storageType === 'sqlite') {
            $dbPath = TestWorker::path('server.sqlite');

            foreach ([$dbPath, $dbPath . '-wal', $dbPath . '-shm'] as $path) {
                if (file_exists($path)) {
                    unlink($path);
                }
            }

            return PdoConfig::forSqlite($dbPath);
        }

        if ($storageType === 'mysql') {
            $dsn = getenv('MYSQL_DSN') ?: 'mysql:host=127.0.0.1;port=3306;dbname=freedsx';
            $user = getenv('MYSQL_USER') ?: 'root';
            $password = getenv('MYSQL_PASSWORD') ?: 'root';

            $cleanup = new PDO(
                $dsn,
                $user,
                $password,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            );
            $cleanup->exec('DROP TABLE IF EXISTS ldap_replica_pwpolicy_state');
            $cleanup->exec('DROP TABLE IF EXISTS entry_attribute_values');
            $cleanup->exec('DROP TABLE IF EXISTS entries');
            unset($cleanup);

            return PdoConfig::forMysql($dsn, $user, $password);
        }

        return InMemoryStorageConfig::withEntries();
    }
}
