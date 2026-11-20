<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\PasswordConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\Config\Replication\ConsumerConfig;
use FreeDSx\Ldap\Server\Config\ReplicationConfig;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\ServerOptions;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Process\Process;

/**
 * Runs a read-only replica of a provider it spawns locally, mirroring it over RFC 4533.
 */
final class LdapReplicaCommand extends Command
{
    use ConsoleOptionsTrait;

    /**
     * A subtree the provider hides from the replica's sync identity.
     */
    public const HIDDEN_FROM_SYNC = 'ou=hidden,ou=people,dc=foo,dc=bar';

    /**
     * Tests assert on forwarded bind state, so they should not wait a production drain for it.
     */
    private const FORWARD_INTERVAL = 0.05;

    private const SEED = __DIR__ . '/../resources/seed/sync-seed.ldif';

    protected function configure(): void
    {
        $this
            ->setName('ldap-replica')
            ->setDescription('Run a read-only replica of a locally spawned provider')
            ->addOption('transport', null, InputOption::VALUE_REQUIRED, 'The replica transport.', 'tcp')
            ->addOption('port', null, InputOption::VALUE_REQUIRED, 'The replica listen port.', (string) TestWorker::port())
            ->addOption(
                'provider-port',
                null,
                InputOption::VALUE_REQUIRED,
                'The provider listen port.',
                (string) TestWorker::port(TestWorker::OFFSET_PROVIDER),
            )
            ->addOption('runner', null, InputOption::VALUE_REQUIRED, 'The server runner (pcntl/swoole).', 'pcntl')
            ->addOption('forward', null, InputOption::VALUE_NONE, 'Enable ppolicy-state forwarding to the provider.')
            ->addOption(
                'keep-replica-db',
                null,
                InputOption::VALUE_NONE,
                'Start the replica on the database a previous run left behind.',
            )
            ->addOption(
                'keep-provider-db',
                null,
                InputOption::VALUE_NONE,
                'Start the provider on the database a previous run left behind, without seeding it.',
            )
            ->addOption(
                'provider-changes',
                null,
                InputOption::VALUE_REQUIRED,
                'An LDIF changelog the provider replays before it starts listening.',
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
        $providerPort = (int) $this->getStringOption($input, 'provider-port');
        $runner = $this->getStringOption($input, 'runner');

        if (!in_array($runner, ['pcntl', 'swoole'], true)) {
            $io->error("Invalid --runner value: {$runner}. Expected one of: pcntl, swoole.");

            return Command::FAILURE;
        }

        $provider = $this->startProvider(
            $providerPort,
            $runner,
            $this->providerArgs($input),
        );
        register_shutdown_function(static fn() => $provider->stop());

        $consumerConfig = new ConsumerConfig(
            (new ClientOptions())
                ->setServers(['127.0.0.1'])
                ->setPort($providerPort)
                ->setBaseDn('dc=foo,dc=bar'),
        );
        $consumerConfig->setBind(Operations::bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        ));
        $consumerConfig->setForwardInterval(self::FORWARD_INTERVAL);

        $network = (new NetworkConfig())
            ->setPort($port)
            ->setTransport($transport)
            ->setSocketAcceptTimeout(0.1)
            ->setShutdownTimeout(0);

        $policy = new PasswordPolicy(
            lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: 2,
            ),
        );

        $server = new LdapServer(
            (new ServerOptions(
                storageConfig: $this->createReplicaStorageConfig($input->getOption('keep-replica-db') === true),
                networkConfig: $network,
                runnerConfig: new RunnerConfig($runner === 'swoole' ? RunnerMode::Swoole : RunnerMode::Pcntl),
                replicationConfig: ReplicationConfig::forReplica($consumerConfig),
                passwordConfig: (new PasswordConfig())->setPolicy($policy),
            ))
                ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL)),
        );

        $server->run();

        return Command::SUCCESS;
    }

    /**
     * @return list<string>
     */
    private function providerArgs(InputInterface $input): array
    {
        $args = $input->getOption('keep-provider-db') === true
            ? ['--keep-db']
            : ['--seed=' . self::SEED];

        $changes = $this->getStringOption(
            $input,
            'provider-changes',
        );
        if ($changes !== '') {
            $args[] = '--changes=' . $changes;
        }

        if ($input->getOption('forward') === true) {
            $args[] = '--allow-ppolicy-forward';
            $args[] = '--manager';
        }

        return $args;
    }

    /**
     * @param list<string> $extraArgs
     */
    private function startProvider(
        int $providerPort,
        string $runner,
        array $extraArgs,
    ): Process {
        $provider = new Process([
            'php',
            '-dpcov.enabled=0',
            __DIR__ . '/../bin/ldap-server.php',
            '--transport=tcp',
            '--port=' . $providerPort,
            '--runner=' . $runner,
            '--storage=sqlite',
            '--allow-sync',
            '--hide-from-sync=' . self::HIDDEN_FROM_SYNC,
            ...$extraArgs,
        ]);
        $provider->start();

        $deadline = microtime(true) + 10.0;
        while ($provider->isRunning()) {
            if (str_contains($provider->getOutput(), 'server starting...')) {
                break;
            }

            if (microtime(true) >= $deadline) {
                break;
            }

            usleep(50_000);
        }

        return $provider;
    }

    private function createReplicaStorageConfig(bool $keepDb): PdoConfig
    {
        $dbPath = TestWorker::path('replica.sqlite');

        if ($keepDb) {
            return PdoConfig::forSqlite($dbPath);
        }

        foreach ([$dbPath, $dbPath . '-wal', $dbPath . '-shm'] as $path) {
            if (file_exists($path)) {
                unlink($path);
            }
        }

        return PdoConfig::forSqlite($dbPath);
    }
}
