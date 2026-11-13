<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapProxyServer;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\ProxyServerOptions;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Process\Process;
use Tests\Support\FreeDSx\Ldap\Logging\StdoutLogger;

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
            )
            ->addOption(
                'no-require-authentication',
                null,
                InputOption::VALUE_NONE,
                'Forward operations for sessions that have not bound',
            )
            ->addOption(
                'runner',
                null,
                InputOption::VALUE_REQUIRED,
                'Server runner the proxy accepts clients on (pcntl, swoole)',
                'pcntl',
            )
            ->addOption(
                'workers',
                null,
                InputOption::VALUE_REQUIRED,
                'Swoole worker processes to accept on; more than one uses the pooled runner',
                '1',
            )
            ->addOption(
                'write-timeout',
                null,
                InputOption::VALUE_REQUIRED,
                'Seconds a write may stall before the connection is closed; the library default when omitted',
                '',
            )
            ->addOption(
                'request-read-timeout',
                null,
                InputOption::VALUE_REQUIRED,
                'Seconds a request may take to finish arriving; the library default when omitted',
                '',
            )
            ->addOption(
                'entry-padding',
                null,
                InputOption::VALUE_REQUIRED,
                'Bytes of description the upstream adds to each extra entry',
                '0',
            )
            ->addOption(
                'log',
                null,
                InputOption::VALUE_NONE,
                'Write proxy log messages to stdout, so a test can wait on one instead of sleeping',
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

        $runner = $this->getStringOption($input, 'runner');
        if (!in_array($runner, ['pcntl', 'swoole'], true)) {
            $output->writeln("<error>Invalid --runner value: {$runner}. Expected one of: pcntl, swoole.</error>");

            return Command::FAILURE;
        }

        $upstreamPort = TestWorker::port(TestWorker::OFFSET_UPSTREAM);
        $upstream = $this->startUpstream(
            $upstreamPort,
            $upstreamStartTls,
            $upstreamConfidentiality,
            $this->getStringOption($input, 'entries'),
            $this->getStringOption($input, 'entry-padding'),
        );

        register_shutdown_function(static fn() => $upstream->stop());

        $server = new LdapProxyServer(new ProxyOptions(
            serverOptions: $this->makeServerOptions(
                $input,
                $output,
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
        InputInterface $input,
        OutputInterface $output,
    ): ProxyServerOptions {
        $network = (new NetworkConfig())
            ->setPort(TestWorker::port())
            ->setUseSsl($this->getStringOption($input, 'transport') === 'ssl')
            ->setSslCert(self::SSL_CERT)
            ->setSslCertKey(self::SSL_KEY)
            ->setSocketAcceptTimeout(0.1);

        $writeTimeout = $this->getStringOption($input, 'write-timeout');
        if ($writeTimeout !== '') {
            $network->setWriteTimeout((int) $writeTimeout);
        }
        $requestReadTimeout = $this->getStringOption($input, 'request-read-timeout');
        if ($requestReadTimeout !== '') {
            $network->setRequestReadTimeout((int) $requestReadTimeout);
        }

        return (new ProxyServerOptions($network))
            ->setRunnerConfig(new RunnerConfig(
                $this->getStringOption($input, 'runner') === 'swoole' ? RunnerMode::Swoole : RunnerMode::Pcntl,
                (int) $this->getStringOption($input, 'workers'),
            ))
            ->setRequireAuthentication($input->getOption('no-require-authentication') !== true)
            ->setLogger($input->getOption('log') === true ? new StdoutLogger() : null)
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
        string $entryPadding,
    ): Process {
        $upstream = new Process([
            'php',
            '-dpcov.enabled=0',
            __DIR__ . '/../bin/ldap-server.php',
            // StartTLS upgrades a cleartext listener, while LDAPS needs the socket encrypted from the start.
            '--transport=' . ($useStartTls ? 'tcp' : 'ssl'),
            '--port=' . $port,
            '--entries=' . $entries,
            '--entry-padding=' . $entryPadding,
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
