<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapProxyServer;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\ProxyServerOptions;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Process\Process;

final class LdapProxyCommand extends Command
{
    use ConsoleOptionsTrait;

    private const SSL_KEY = __DIR__ . '/../resources/cert/slapd.key';

    private const SSL_CERT = __DIR__ . '/../resources/cert/slapd.crt';

    private const VALID_CONFIDENTIALITY = ['none', 'bind', 'all'];

    protected function configure(): void
    {
        $this
            ->setName('ldap-proxy')
            ->setDescription('Run the test LDAP proxy and the upstream it forwards to')
            ->addOption(
                'transport',
                null,
                InputOption::VALUE_REQUIRED,
                'Transport clients connect to the proxy over (tcp, ssl)',
                'tcp',
            )
            ->addOption(
                'entries',
                null,
                InputOption::VALUE_REQUIRED,
                'Number of extra entries to seed upstream',
                '12',
            )
            ->addOption(
                'upstream-start-tls',
                null,
                InputOption::VALUE_NONE,
                'Upgrade the upstream hop with StartTLS rather than connecting to it over LDAPS',
            )
            ->addOption(
                'upstream-require-confidentiality',
                null,
                InputOption::VALUE_REQUIRED,
                'Confidentiality the upstream demands: none, bind (credential-bearing binds), or all (every operation)',
                'none',
            )
            ->addOption(
                'require-upstream-confidentiality',
                null,
                InputOption::VALUE_NONE,
                'Refuse to start unless the upstream hop is encrypted',
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        $upstreamStartTls = $input->getOption('upstream-start-tls') === true;
        $upstreamConfidentiality = $this->getStringOption($input, 'upstream-require-confidentiality');

        if (!in_array($upstreamConfidentiality, self::VALID_CONFIDENTIALITY, true)) {
            $output->writeln(sprintf(
                '<error>Invalid --upstream-require-confidentiality value: %s. Expected one of: %s.</error>',
                $upstreamConfidentiality,
                implode(', ', self::VALID_CONFIDENTIALITY),
            ));

            return Command::FAILURE;
        }

        $upstreamPort = TestWorker::port(TestWorker::OFFSET_UPSTREAM);
        $upstream = $this->startUpstream(
            $upstreamPort,
            $upstreamStartTls,
            $upstreamConfidentiality,
            $this->getStringOption($input, 'entries'),
        );

        register_shutdown_function(static fn() => $upstream->stop());

        $server = new LdapProxyServer(new ProxyOptions(
            serverOptions: $this->makeServerOptions(
                $output,
                $this->getStringOption($input, 'transport') === 'ssl',
            ),
            clientOptions: (new ClientOptions())
                ->setServers(['127.0.0.1'])
                ->setPort($upstreamPort)
                ->setUseSsl(!$upstreamStartTls)
                ->setSslValidateCert(false)
                ->setSslAllowSelfSigned(true),
            useStartTls: $upstreamStartTls,
            requireUpstreamConfidentiality: $input->getOption('require-upstream-confidentiality') === true,
        ));
        $server->run();

        return Command::SUCCESS;
    }

    private function makeServerOptions(
        OutputInterface $output,
        bool $useSsl,
    ): ProxyServerOptions {
        return (new ProxyServerOptions((new NetworkConfig())
            ->setPort(TestWorker::port())
            ->setUseSsl($useSsl)
            ->setSslCert(self::SSL_CERT)
            ->setSslCertKey(self::SSL_KEY)
            ->setSocketAcceptTimeout(0.1)))
            ->setOnServerReady(fn() => $output->writeln('server starting...'));
    }

    /**
     * The proxy owns its upstream, so tests get both from one process tree.
     */
    private function startUpstream(
        int $port,
        bool $useStartTls,
        string $confidentiality,
        string $entries,
    ): Process {
        $upstream = new Process([
            'php',
            '-dpcov.enabled=0',
            __DIR__ . '/../bin/ldap-server.php',
            // StartTLS upgrades a cleartext listener, while LDAPS needs the socket encrypted from the start.
            '--transport=' . ($useStartTls ? 'tcp' : 'ssl'),
            '--port=' . $port,
            '--entries=' . $entries,
            '--require-confidentiality=' . $confidentiality,
        ]);
        $upstream->start();

        $deadline = microtime(true) + 10.0;
        while ($upstream->isRunning()) {
            if (str_contains($upstream->getOutput(), 'server starting...')) {
                break;
            }
            if (microtime(true) >= $deadline) {
                break;
            }
            usleep(50_000);
        }

        return $upstream;
    }
}
