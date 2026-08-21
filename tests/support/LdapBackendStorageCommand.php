<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\RelocationAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\RelocationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\JsonStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use FreeDSx\Ldap\Server\Backend\Storage\SeedOptions;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;
use FreeDSx\Ldap\Schema\LdifSchemaSource;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\Replication\ProviderConfig;
use FreeDSx\Ldap\Server\Config\ReplicationConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\JsonLinesAuditSink;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Config\SchemaConfig;
use FreeDSx\Ldap\ServerOptions;
use PDO;
use RuntimeException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class LdapBackendStorageCommand extends Command
{
    use ConsoleOptionsTrait;

    public const MANAGER_DN = 'cn=manager';

    public const MANAGER_PASSWORD = 'manager-pass';

    public const ROOT_DN = 'dc=foo,dc=bar';

    /**
     * Holds ModifyDn without administrator rights, so a rename it performs is held to the per-entry rules.
     */
    public const MOVER_DN = 'cn=mover,dc=foo,dc=bar';

    public const MOVER_PASSWORD = '12345';

    /**
     * Entries may be renamed inside this container but never moved out of it.
     */
    public const PINNED_CONTAINER_DN = 'ou=pinned,dc=foo,dc=bar';

    /**
     * Nothing may be moved into this container.
     */
    public const SEALED_CONTAINER_DN = 'ou=sealed,dc=foo,dc=bar';

    /**
     * Tests assert on replicated state, so they should not wait a production poll for it.
     */
    private const SYNC_POLL_INTERVAL = 0.05;

    /**
     * Serve sync to consumers, which records every write to the journal as a side effect.
     */
    private const JOURNAL_SYNC = 'sync';

    /**
     * Record every write for auditing, without serving sync.
     */
    private const JOURNAL_AUDIT = 'audit';

    /**
     * The value when --journal is absent; passing it without one means {@see self::JOURNAL_SYNC}.
     */
    private const JOURNAL_OFF = 'off';

    /**
     * The fixed directory content every suite using this harness starts from.
     */
    private const SEED_LDIF = __DIR__ . '/../resources/seed/backend-storage-seed.ldif';

    protected function configure(): void
    {
        $this
            ->setName('ldap-backend-storage')
            ->setDescription('Run the test LDAP server with a pluggable storage backend')
            ->addOption(
                'transport',
                null,
                InputOption::VALUE_REQUIRED,
                'Transport type (tcp, unix)',
                'tcp',
            )
            ->addOption(
                'storage',
                null,
                InputOption::VALUE_REQUIRED,
                'Storage adapter (memory, json, sqlite, mysql)',
                'memory',
            )
            ->addOption(
                'runner',
                null,
                InputOption::VALUE_REQUIRED,
                'Server runner (pcntl, swoole)',
                'pcntl',
            )
            ->addOption(
                'swoole-workers',
                null,
                InputOption::VALUE_REQUIRED,
                'Swoole worker processes: 1 for a single process, 0 to auto-detect the CPU count',
                '1',
            )
            ->addOption(
                'port',
                null,
                InputOption::VALUE_REQUIRED,
                'Port to listen on',
                (string) TestWorker::port(),
            )
            ->addOption(
                'seed-entries',
                null,
                InputOption::VALUE_REQUIRED,
                'Number of additional seed entries to generate',
                '0',
            )
            ->addOption(
                'seed-attributes',
                null,
                InputOption::VALUE_REQUIRED,
                'Filler attributes added to each seed entry to widen the return path (0 = none)',
                '0',
            )
            ->addOption(
                'validation-mode',
                null,
                InputOption::VALUE_REQUIRED,
                'Schema validation mode (strict, lenient, off)',
                'strict',
            )
            ->addOption(
                'schema-ldif',
                null,
                InputOption::VALUE_REQUIRED,
                'Path to a subschema LDIF file whose definitions are merged into the schema',
                '',
            )
            ->addOption(
                'allow-relax',
                null,
                InputOption::VALUE_NONE,
                'Grant the Relax Rules control to authenticated identities',
            )
            ->addOption(
                'allow-proxy',
                null,
                InputOption::VALUE_NONE,
                'Grant cn=user the Proxied Authorization control for identities under ou=people',
            )
            ->addOption(
                'open-monitor',
                null,
                InputOption::VALUE_NONE,
                'Loosen cn=monitor from the administrators-only default to any authenticated identity',
            )
            ->addOption(
                'hide-rootdse-vendor',
                null,
                InputOption::VALUE_NONE,
                'Deny reads of the Root DSE vendorName attribute, to exercise per-attribute policy on it',
            )
            ->addOption(
                'admin-only-subschema',
                null,
                InputOption::VALUE_NONE,
                'Tighten cn=Subschema from the authenticated default to the administrators group',
            )
            ->addOption(
                'manager',
                null,
                InputOption::VALUE_NONE,
                'Configure a break-glass manager identity (cn=manager) so tests can read userPassword back',
            )
            ->addOption(
                'monitor',
                null,
                InputOption::VALUE_NONE,
                'Enable the cn=monitor entry',
            )
            ->addOption(
                'journal',
                null,
                InputOption::VALUE_OPTIONAL,
                sprintf(
                    'Record writes to the change journal: "%s" also serves them to consumers, "%s" only logs them',
                    self::JOURNAL_SYNC,
                    self::JOURNAL_AUDIT,
                ),
                self::JOURNAL_OFF,
            )
            ->addOption(
                'max-search-lookthrough',
                null,
                InputOption::VALUE_REQUIRED,
                'Maximum entries examined per search before adminLimitExceeded (0 = no limit)',
                '0',
            )
            ->addOption(
                'max-search-size',
                null,
                InputOption::VALUE_REQUIRED,
                'Maximum entries returned per search (0 = no limit)',
                '0',
            )
            ->addOption(
                'max-paging-sessions',
                null,
                InputOption::VALUE_REQUIRED,
                'Maximum concurrent paging sessions before the oldest is aged out',
                '25',
            )
            ->addOption(
                'seed-ldif',
                null,
                InputOption::VALUE_REQUIRED,
                'Path to the LDIF seeded at startup',
                self::SEED_LDIF,
            )
            ->addOption(
                'no-seed-validation',
                null,
                InputOption::VALUE_NONE,
                'Seed without schema validation, for fixtures the configured schema deliberately does not cover',
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        $io = new SymfonyStyle($input, $output);

        $transport = $this->getStringOption($input, 'transport');
        $storage = $this->getStringOption($input, 'storage');
        $runner = $this->getStringOption($input, 'runner');
        $port = (int) $this->getStringOption($input, 'port');
        $seedEntries = (int) $this->getStringOption($input, 'seed-entries');
        $seedAttributes = (int) $this->getStringOption($input, 'seed-attributes');

        if (!in_array($storage, ['memory', 'json', 'sqlite', 'mysql'], true)) {
            $io->error("Invalid --storage value: {$storage}. Expected one of: memory, json, sqlite, mysql.");

            return Command::FAILURE;
        }

        if (!in_array($runner, ['pcntl', 'swoole'], true)) {
            $io->error("Invalid --runner value: {$runner}. Expected one of: pcntl, swoole.");

            return Command::FAILURE;
        }

        if ($seedEntries < 0) {
            $io->error("Invalid --seed-entries value: {$seedEntries}. Must be zero or greater.");

            return Command::FAILURE;
        }

        if ($seedAttributes < 0) {
            $io->error("Invalid --seed-attributes value: {$seedAttributes}. Must be zero or greater.");

            return Command::FAILURE;
        }

        $validationMode = match ($this->getStringOption($input, 'validation-mode')) {
            'strict' => SchemaValidationMode::Strict,
            'lenient' => SchemaValidationMode::Lenient,
            'off' => SchemaValidationMode::Off,
            default => null,
        };

        if ($validationMode === null) {
            $io->error('Invalid --validation-mode value. Expected one of: strict, lenient, off.');

            return Command::FAILURE;
        }

        // The fixed content comes from SEED_LDIF; only the generated entries are built here.
        $entries = [];

        for ($i = 1; $i <= $seedEntries; $i++) {
            $attributes = [
                new Attribute('cn', "seed-{$i}"),
                new Attribute('objectClass', 'inetOrgPerson', 'extensibleObject'),
                new Attribute('sn', 'Seeded'),
                new Attribute('mail', "seed-{$i}@foo.bar"),
                new Attribute('uidNumber', (string) (1000 + $i)),
            ];

            // Distinct option subtypes of a defined, non-filtered, non-indexed base type widen the return path.
            for ($k = 1; $k <= $seedAttributes; $k++) {
                $attributes[] = new Attribute("initials;filler-{$k}", "filler-{$i}-{$k}");
            }

            $entries[] = new Entry(
                new Dn("cn=seed-{$i},ou=people,dc=foo,dc=bar"),
                ...$attributes,
            );
        }

        $network = (new NetworkConfig())
            ->setPort($port)
            ->setTransport($transport)
            ->setSocketAcceptTimeout(0.1);

        $serverOptions = (new ServerOptions(
            networkConfig: $network,
            schemaConfig: $this->buildSchemaConfig(
                $validationMode,
                $this->getStringOption($input, 'schema-ldif'),
            ),
        ))
            ->setAdministrators(Subject::group('cn=admins,dc=foo,dc=bar'))
            ->setMonitorEnabled((bool) $input->getOption('monitor'))
            ->setMaxSearchLookthrough((int) $this->getStringOption($input, 'max-search-lookthrough'))
            ->setMaxSearchSize((int) $this->getStringOption($input, 'max-search-size'))
            ->setMaxPagingSessions((int) $this->getStringOption($input, 'max-paging-sessions'))
            ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL));

        $this->applyJournalMode($serverOptions, $input);

        if ($input->getOption('allow-relax')) {
            $serverOptions->setAclRules(
                $serverOptions->getAclRules()->appendControlRules(
                    ControlRule::allow(
                        Subject::authenticated(),
                        Target::any(),
                        Control::OID_RELAX_RULES,
                    ),
                ),
            );
        }

        if ($input->getOption('allow-proxy')) {
            $serverOptions->setAclRules(
                $serverOptions->getAclRules()->appendControlRules(
                    ControlRule::allow(
                        Subject::dn('cn=user,dc=foo,dc=bar'),
                        Target::subtree('ou=people,dc=foo,dc=bar'),
                        Control::OID_PROXY_AUTHORIZATION,
                    ),
                ),
            );
        }

        if ($input->getOption('admin-only-subschema')) {
            $serverOptions->setAclRules(
                $serverOptions->getAclRules()->withSubschemaAccess(
                    Subject::group('cn=admins,dc=foo,dc=bar'),
                    $serverOptions->getSubschemaEntry(),
                ),
            );
        }

        if ($input->getOption('open-monitor')) {
            $serverOptions->setAclRules(
                $serverOptions->getAclRules()->withMonitorAccess(Subject::authenticated()),
            );
        }

        if ($input->getOption('hide-rootdse-vendor')) {
            // Prepended rather than appended, since a deny only takes effect if it is matched first.
            $rules = $serverOptions->getAclRules();
            $serverOptions->setAclRules(
                $rules->replaceAttributeRules(
                    AttributeRule::deny(
                        Subject::anyone(),
                        Target::dn(''),
                        'vendorName',
                    )->forRead(),
                    ...$rules->attributes,
                ),
            );
        }

        $this->grantSubtreeMoves($serverOptions);

        if ($input->getOption('manager')) {
            $serverOptions->setManager(new ManagerIdentity(
                new Dn(self::MANAGER_DN),
                '{SHA}' . base64_encode(sha1(self::MANAGER_PASSWORD, true)),
            ));
        }

        if ($storage === 'memory') {
            $config = InMemoryStorageConfig::withEntries();
        } elseif ($storage === 'json') {
            $filePath = TestWorker::path('backend_storage.json');

            if (file_exists($filePath)) {
                unlink($filePath);
            }

            $config = JsonStorageConfig::forFile($filePath);
        } elseif ($storage === 'sqlite') {
            $dbPath = TestWorker::path('backend_storage.sqlite');

            foreach ([$dbPath, $dbPath . '-wal', $dbPath . '-shm'] as $path) {
                if (file_exists($path)) {
                    unlink($path);
                }
            }

            $config = PdoConfig::forSqlite($dbPath);
        } else {
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
            $cleanup->exec('DROP TABLE IF EXISTS entry_attribute_trigrams');
            $cleanup->exec('DROP TABLE IF EXISTS entry_attribute_values');
            $cleanup->exec('DROP TABLE IF EXISTS entries');
            unset($cleanup);

            $config = PdoConfig::forMysql($dsn, $user, $password);
        }

        $serverOptions
            ->setStorageConfig($config)
            ->setRunnerConfig(new RunnerConfig(
                $runner === 'swoole' ? RunnerMode::Swoole : RunnerMode::Pcntl,
                (int) $this->getStringOption($input, 'swoole-workers'),
            ));

        $container = Container::forServer($serverOptions);
        $server = new LdapServer(
            $serverOptions,
            $container,
        );

        $seedLdif = $this->getStringOption($input, 'seed-ldif');
        $validateSeed = !$input->getOption('no-seed-validation');

        $seed = function () use ($server, $entries, $container, $seedLdif, $validateSeed): void {
            $server->seed(
                new FileLdifLoader($seedLdif),
                new SeedOptions(ignoreValidation: !$validateSeed),
            );

            // The generated entries stay a raw import, since they exist to widen the return path rather than to
            // be valid directory content.
            if ($entries !== []) {
                (new LdapImporter($container->get(EntryStorageInterface::class)))->importEntries($entries);
            }
        };

        if ($runner === 'swoole') {
            \Swoole\Coroutine\run($seed);
        } else {
            $seed();
        }

        $server->run();

        return Command::SUCCESS;
    }

    /**
     * Lets cn=mover rename entries without administrator rights, while pinning one container shut.
     */
    private function grantSubtreeMoves(ServerOptions $serverOptions): void
    {
        $mover = Subject::dn(self::MOVER_DN);

        $serverOptions->setAclRules(
            $serverOptions->getAclRules()
                ->appendOperationRules(
                    OperationRule::allow(
                        $mover,
                        Target::subtree(self::ROOT_DN),
                        OperationType::ModifyDn,
                    ),
                )
                ->appendAttributeRules(
                    AttributeRule::allow(
                        $mover,
                        Target::subtree(self::ROOT_DN),
                        'cn',
                        'ou',
                    )->forWrite(),
                )
                // Denies first, since the first match wins.
                ->appendRelocationRules(
                    RelocationRule::deny(
                        $mover,
                        Target::subtree(self::PINNED_CONTAINER_DN),
                        RelocationAccess::Out,
                    ),
                    RelocationRule::deny(
                        $mover,
                        Target::subtree(self::SEALED_CONTAINER_DN),
                        RelocationAccess::In,
                    ),
                    RelocationRule::allow(
                        $mover,
                        Target::subtree(self::ROOT_DN),
                    ),
                ),
        );
    }

    /**
     * Audit mode journals without a replication role, so nothing is served to consumers.
     */
    private function applyJournalMode(
        ServerOptions $serverOptions,
        InputInterface $input,
    ): void {
        // Symfony hands back null when the option is passed without a value.
        $mode = $input->getOption('journal') ?? self::JOURNAL_SYNC;

        match ($mode) {
            self::JOURNAL_SYNC => $serverOptions->setReplicationConfig(ReplicationConfig::forProvider(
                (new ProviderConfig())->setPollInterval(self::SYNC_POLL_INTERVAL),
            )),
            self::JOURNAL_AUDIT => $serverOptions->setChangeJournalConfig(new ChangeJournalConfig(
                auditSink: new JsonLinesAuditSink(TestWorker::path('audit.jsonl')),
            )),
            self::JOURNAL_OFF => $serverOptions,
            default => throw new RuntimeException(sprintf(
                'Unknown --journal mode "%s".',
                is_string($mode) ? $mode : gettype($mode),
            )),
        };
    }

    private function buildSchemaConfig(
        SchemaValidationMode $validationMode,
        string $schemaLdif,
    ): SchemaConfig {
        $config = (new SchemaConfig())
            ->setValidationMode($validationMode);

        if ($schemaLdif !== '') {
            $config->addSource(new LdifSchemaSource($schemaLdif));
        }

        return $config;
    }
}
