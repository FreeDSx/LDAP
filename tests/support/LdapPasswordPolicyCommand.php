<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\ServerOptions;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class LdapPasswordPolicyCommand extends Command
{
    use ConsoleOptionsTrait;

    private const ADMIN_DN = 'cn=admin,dc=foo,dc=bar';

    private const SSL_KEY = __DIR__ . '/../resources/cert/slapd.key';

    private const SSL_CERT = __DIR__ . '/../resources/cert/slapd.crt';

    private const POLICY_SEED_LDIF = __DIR__ . '/../resources/seed/password-policy-seed.ldif';

    private const SUBENTRY_SEED_LDIF = __DIR__ . '/../resources/seed/subentry-policy-seed.ldif';

    protected function configure(): void
    {
        $this
            ->setName('ldap-password-policy')
            ->setDescription('Run the test LDAP server with server-side password policy enabled')
            ->addOption(
                'transport',
                null,
                InputOption::VALUE_REQUIRED,
                'Transport type (tcp, unix)',
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
                'subentry-policy',
                null,
                InputOption::VALUE_NONE,
                'Seed a pwdPolicy subentry under an administrative point instead of configuring a policy in PHP',
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        $transport = $this->getStringOption($input, 'transport');
        $port = (int) $this->getStringOption($input, 'port');
        $useSubentries = $input->getOption('subentry-policy') === true;

        $network = (new NetworkConfig())
            ->setPort($port)
            ->setTransport($transport)
            // StartTLS has to be reachable, since the reset gate is required to permit it.
            ->setSslCert(self::SSL_CERT)
            ->setSslCertKey(self::SSL_KEY)
            ->setSocketAcceptTimeout(0.1);

        $dbPath = TestWorker::path('password_policy.sqlite');

        foreach ([$dbPath, $dbPath . '-wal', $dbPath . '-shm'] as $path) {
            if (file_exists($path)) {
                unlink($path);
            }
        }

        $options = (new ServerOptions(
            PdoConfig::forSqlite($dbPath),
            networkConfig: $network,
        ))
            ->setSaslMechanisms(ServerOptions::SASL_PLAIN)
            ->setAdministrators(Subject::dn(self::ADMIN_DN))
            ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL));

        // Left unset for the subentry run, so any enforcement observed can only come from the DIT.
        if (!$useSubentries) {
            $options->getPasswordConfig()
                // pwdMustChange is what makes the seeded pwdReset binding, per draft-behera-11 7.2.
                ->setPolicy(new PasswordPolicy(
                    change: new PasswordChangeRules(mustChange: true),
                ));
        }

        $server = new LdapServer($options);
        $server->seed(new FileLdifLoader(
            $useSubentries
                ? self::SUBENTRY_SEED_LDIF
                : self::POLICY_SEED_LDIF,
        ));
        $server->run();

        return Command::SUCCESS;
    }
}
