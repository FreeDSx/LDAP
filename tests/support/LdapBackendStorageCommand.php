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
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Config\JsonStorageConfig;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use FreeDSx\Ldap\Schema\NisSchemaProvider;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\StandardSchemaProvider;
use FreeDSx\Ldap\ServerOptions;
use PDO;
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
                'port',
                null,
                InputOption::VALUE_REQUIRED,
                'Port to listen on',
                '10389',
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
                'max-search-lookthrough',
                null,
                InputOption::VALUE_REQUIRED,
                'Maximum entries examined per search before adminLimitExceeded (0 = no limit)',
                '0',
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

        $passwordHash = '{SHA}' . base64_encode(sha1('12345', true));

        $entries = [
            new Entry(
                new Dn('dc=foo,dc=bar'),
                new Attribute('dc', 'foo'),
                new Attribute('objectClass', 'domain'),
            ),
            new Entry(
                new Dn('cn=user,dc=foo,dc=bar'),
                new Attribute('cn', 'user'),
                new Attribute('sn', 'Admin'),
                new Attribute('objectClass', 'inetOrgPerson'),
                new Attribute('userPassword', $passwordHash),
            ),
            new Entry(
                new Dn('ou=people,dc=foo,dc=bar'),
                new Attribute('ou', 'people'),
                new Attribute('objectClass', 'organizationalUnit'),
            ),
            new Entry(
                new Dn('cn=alice,ou=people,dc=foo,dc=bar'),
                new Attribute('cn', 'alice'),
                new Attribute('objectClass', 'inetOrgPerson', 'extensibleObject'),
                new Attribute('sn', 'Smith'),
                new Attribute('mail', 'alice@foo.bar'),
                new Attribute('uidNumber', '99'),
            ),
            new Entry(
                new Dn('cn=nosn,dc=foo,dc=bar'),
                new Attribute('cn', 'nosn'),
                new Attribute('objectClass', 'groupOfNames'),
                new Attribute('member', 'cn=user,dc=foo,dc=bar'),
            ),
        ];

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

        $serverOptions = (new ServerOptions())
            ->setPort($port)
            ->setTransport($transport)
            ->setSocketAcceptTimeout(0.1)
            ->setSchemaValidationMode($validationMode)
            ->setSchema(StandardSchemaProvider::buildCore()->merge(NisSchemaProvider::build()))
            ->setMonitorEnabled((bool) $input->getOption('monitor'))
            ->setMaxSearchLookthrough((int) $this->getStringOption($input, 'max-search-lookthrough'))
            ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL));

        if ($input->getOption('allow-relax')) {
            // Compose on the current rules (the secure default): grant the relax control.
            $serverOptions->setAclRules(
                $serverOptions->getAclRules()->withControlRules(
                    ControlRule::allow(
                        Subject::authenticated(),
                        Target::any(),
                        Control::OID_RELAX_RULES,
                    ),
                ),
            );
        }

        if ($input->getOption('allow-proxy')) {
            // Compose on the current rules (the secure default): grant cn=user proxied-auth over ou=people.
            $serverOptions->setAclRules(
                $serverOptions->getAclRules()->withControlRules(
                    ControlRule::allow(
                        Subject::dn('cn=user,dc=foo,dc=bar'),
                        Target::subtree('ou=people,dc=foo,dc=bar'),
                        Control::OID_PROXY_AUTHORIZATION,
                    ),
                ),
            );
        }

        if ($input->getOption('manager')) {
            $serverOptions->setManager(new ManagerIdentity(
                new Dn(self::MANAGER_DN),
                '{SHA}' . base64_encode(sha1(self::MANAGER_PASSWORD, true)),
            ));
        }

        if ($storage === 'memory') {
            $config = InMemoryStorageConfig::withEntries($entries);
        } elseif ($storage === 'json') {
            $filePath = sys_get_temp_dir() . '/ldap_test_backend_storage.json';

            if (file_exists($filePath)) {
                unlink($filePath);
            }

            $config = JsonStorageConfig::forFile($filePath);
        } elseif ($storage === 'sqlite') {
            $dbPath = sys_get_temp_dir() . '/ldap_test_backend_storage.sqlite';

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
            ->setRunner($runner === 'swoole' ? RunnerMode::Swoole : RunnerMode::Pcntl);

        $container = Container::forServer($serverOptions);
        $server = new LdapServer(
            $serverOptions,
            $container,
        );

        // The in-memory config carries its seed entries; other backends get a raw import (no schema validation).
        if ($storage !== 'memory') {
            $importer = new LdapImporter($container->get(EntryStorageInterface::class));

            if ($runner === 'swoole') {
                \Swoole\Coroutine\run(fn() => $importer->importEntries($entries));
            } else {
                $importer->importEntries($entries);
            }
        }

        $server->run();

        return Command::SUCCESS;
    }
}
