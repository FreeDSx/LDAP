<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\ServerOptions;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class LdapAclCommand extends Command
{
    use ConsoleOptionsTrait;

    protected function configure(): void
    {
        $this
            ->setName('ldap-acl')
            ->setDescription('Run the test LDAP server with ACL rules')
            ->addOption(
                'transport',
                null,
                InputOption::VALUE_REQUIRED,
                'Transport type (tcp, unix)',
                'tcp',
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        $transport = $this->getStringOption($input, 'transport');

        $adminPasswordHash = '{SHA}' . base64_encode(sha1('adminpass', true));
        $userPasswordHash = '{SHA}' . base64_encode(sha1('12345', true));
        $alicePasswordHash = '{SHA}' . base64_encode(sha1('alicepass', true));

        $entries = [
            new Entry(
                new Dn('dc=foo,dc=bar'),
                new Attribute('dc', 'foo'),
                new Attribute('objectClass', 'domain'),
            ),
            new Entry(
                new Dn('cn=admins,dc=foo,dc=bar'),
                new Attribute('cn', 'admins'),
                new Attribute('objectClass', 'groupOfNames'),
                new Attribute('member', 'cn=admin,dc=foo,dc=bar'),
            ),
            new Entry(
                new Dn('cn=admin,dc=foo,dc=bar'),
                new Attribute('cn', 'admin'),
                new Attribute('sn', 'Admin'),
                new Attribute('objectClass', 'inetOrgPerson'),
                new Attribute('userPassword', $adminPasswordHash),
            ),
            new Entry(
                new Dn('cn=user,dc=foo,dc=bar'),
                new Attribute('cn', 'user'),
                new Attribute('sn', 'User'),
                new Attribute('objectClass', 'inetOrgPerson'),
                new Attribute('userPassword', $userPasswordHash),
            ),
            new Entry(
                new Dn('ou=people,dc=foo,dc=bar'),
                new Attribute('ou', 'people'),
                new Attribute('objectClass', 'organizationalUnit'),
            ),
            new Entry(
                new Dn('cn=alice,ou=people,dc=foo,dc=bar'),
                new Attribute('cn', 'alice'),
                new Attribute('sn', 'Smith'),
                new Attribute('objectClass', 'inetOrgPerson'),
                new Attribute('userPassword', $alicePasswordHash),
            ),
        ];

        $server = new LdapServer(
            (new ServerOptions())
                ->setPort(10389)
                ->setTransport($transport)
                ->setSocketAcceptTimeout(0.1)
                ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL))
                ->setAclRules(
                    (AclRules::fromEmpty())
                        ->withOperationRules(
                            OperationRule::allow(
                                Subject::group('cn=admins,dc=foo,dc=bar'),
                            ),
                            OperationRule::allow(
                                Subject::authenticated(),
                                Target::any(),
                                OperationType::Search,
                                OperationType::Compare,
                            ),
                            OperationRule::allow(
                                Subject::authenticated(),
                                Target::subtree('ou=people,dc=foo,dc=bar'),
                                OperationType::ModifyDn,
                            ),
                            OperationRule::allow(
                                Subject::self(),
                                Target::any(),
                                OperationType::Modify,
                            ),
                            OperationRule::deny(Subject::anyone()),
                        )
                        ->withAttributeRules(
                            AttributeRule::allow(
                                Subject::self(),
                                Target::any(),
                                'userPassword',
                            ),
                            AttributeRule::allow(
                                Subject::group('cn=admins,dc=foo,dc=bar'),
                                Target::any(),
                                'userPassword',
                            ),
                            AttributeRule::deny(
                                Subject::anyone(),
                                Target::any(),
                                'userPassword',
                            ),
                        ),
                ),
        );

        $server->getOptions()->setStorageConfig(InMemoryStorageConfig::withEntries($entries));
        $server->run();

        return Command::SUCCESS;
    }
}
