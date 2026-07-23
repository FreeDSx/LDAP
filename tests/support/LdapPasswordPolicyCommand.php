<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\ServerOptions;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class LdapPasswordPolicyCommand extends Command
{
    use ConsoleOptionsTrait;

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
                '10389',
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        $transport = $this->getStringOption($input, 'transport');
        $port = (int) $this->getStringOption($input, 'port');
        // Plaintext so both simple bind and SASL PLAIN can verify against the stored value.
        $password = '12345';

        $entries = [
            new Entry(
                new Dn('dc=foo,dc=bar'),
                new Attribute('dc', 'foo'),
                new Attribute('objectClass', 'domain'),
            ),
            new Entry(
                new Dn('cn=user,dc=foo,dc=bar'),
                new Attribute('cn', 'user'),
                new Attribute('uid', 'user'),
                new Attribute('sn', 'User'),
                new Attribute('objectClass', 'inetOrgPerson'),
                new Attribute('userPassword', $password),
            ),
            new Entry(
                new Dn('cn=reset-user,dc=foo,dc=bar'),
                new Attribute('cn', 'reset-user'),
                new Attribute('uid', 'reset-user'),
                new Attribute('sn', 'Reset'),
                new Attribute('objectClass', 'inetOrgPerson'),
                new Attribute('userPassword', $password),
                new Attribute(PasswordPolicyOid::NAME_PWD_RESET, 'TRUE'),
            ),
        ];

        $server = new LdapServer(
            (new ServerOptions())
                ->setPort($port)
                ->setTransport($transport)
                ->setSocketAcceptTimeout(0.1)
                ->setPasswordPolicy(new PasswordPolicy())
                ->setSaslMechanisms(ServerOptions::SASL_PLAIN)
                ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL)),
        );
        $server->getOptions()->setStorageConfig(InMemoryStorageConfig::withEntries($entries));
        $server->run();

        return Command::SUCCESS;
    }
}
