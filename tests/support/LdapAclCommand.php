<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Schema\LdifSchemaSource;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\SchemaConfig;
use FreeDSx\Ldap\ServerOptions;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class LdapAclCommand extends Command
{
    use ConsoleOptionsTrait;

    public const SECRET_CODE = 'S3CR3T-alice';

    /**
     * An identity that may modify its own entry but may not search it, so read policy and write policy diverge.
     */
    public const HIDDEN_DN = 'cn=hidden,ou=people,dc=foo,dc=bar';

    public const HIDDEN_PASSWORD = 'hiddenpass';

    /**
     * Holds every attribute write under ou=people, so the userPassword deny is the only thing stopping it.
     */
    public const DELEGATE_DN = 'cn=delegate,dc=foo,dc=bar';

    public const DELEGATE_PASSWORD = 'delegatepass';

    /**
     * Defines secretCode as confidential; loaded so the harness exercises the same path an operator would.
     */
    private const SECRET_CODE_SCHEMA = __DIR__ . '/../resources/schema/acl-secret-code.ldif';

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

        $adminPasswordHash = '{SHA}' . base64_encode(sha1('12345', true));
        $userPasswordHash = '{SHA}' . base64_encode(sha1('12345', true));
        $alicePasswordHash = '{SHA}' . base64_encode(sha1('alicepass', true));
        $hiddenPasswordHash = '{SHA}' . base64_encode(sha1(self::HIDDEN_PASSWORD, true));
        $delegatePasswordHash = '{SHA}' . base64_encode(sha1(self::DELEGATE_PASSWORD, true));

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
                new Attribute('objectClass', 'inetOrgPerson', 'extensibleObject'),
                new Attribute('userPassword', $alicePasswordHash),
                new Attribute('secretCode', self::SECRET_CODE),
            ),
            // RDN is uid, which is not writable under ou=people, so a rename that touches it must be refused.
            new Entry(
                new Dn('uid=bob,ou=people,dc=foo,dc=bar'),
                new Attribute('uid', 'bob'),
                new Attribute('cn', 'bob'),
                new Attribute('sn', 'Bob'),
                new Attribute('objectClass', 'inetOrgPerson'),
            ),
            new Entry(
                new Dn('uid=bob2,ou=people,dc=foo,dc=bar'),
                new Attribute('uid', 'bob2'),
                new Attribute('cn', 'bob2'),
                new Attribute('sn', 'Bob'),
                new Attribute('objectClass', 'inetOrgPerson'),
            ),
            new Entry(
                new Dn(self::DELEGATE_DN),
                new Attribute('cn', 'delegate'),
                new Attribute('sn', 'Delegate'),
                new Attribute('objectClass', 'inetOrgPerson'),
                new Attribute('userPassword', $delegatePasswordHash),
            ),
            new Entry(
                new Dn(self::HIDDEN_DN),
                new Attribute('cn', 'hidden'),
                new Attribute('sn', 'Hidden'),
                new Attribute('objectClass', 'inetOrgPerson'),
                new Attribute('userPassword', $hiddenPasswordHash),
            ),
        ];

        $network = (new NetworkConfig())
            ->setPort(10389)
            ->setTransport($transport)
            ->setSocketAcceptTimeout(0.1);

        $server = new LdapServer(
            (new ServerOptions(
                networkConfig: $network,
                schemaConfig: (new SchemaConfig())->addSource(
                    new LdifSchemaSource(self::SECRET_CODE_SCHEMA),
                ),
            ))
                ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL))
                ->setAclRules(
                    (AclRules::fromEmpty())
                        ->replaceOperationRules(
                            OperationRule::allow(
                                Subject::group('cn=admins,dc=foo,dc=bar'),
                            ),
                            // Ahead of the blanket search grant, so this entry stays writable by its own identity
                            // while being unreadable to everyone but an administrator.
                            OperationRule::deny(
                                Subject::anyone(),
                                Target::dn(self::HIDDEN_DN),
                                OperationType::Search,
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
                        ->replaceAttributeRules(
                            // Self may set its own password but never read it back.
                            AttributeRule::allow(
                                Subject::self(),
                                Target::any(),
                                'userPassword',
                            )->forWrite(),
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
                            // Writes are denied unless a rule allows them, so mirror the operation grants above.
                            AttributeRule::allow(
                                Subject::group('cn=admins,dc=foo,dc=bar'),
                                Target::any(),
                            )->forWrite(),
                            AttributeRule::allow(
                                Subject::self(),
                                Target::any(),
                            )->forWrite(),
                            // A rename writes the RDN attribute, so delegating renames means granting it too.
                            AttributeRule::allow(
                                Subject::authenticated(),
                                Target::subtree('ou=people,dc=foo,dc=bar'),
                                'cn',
                            )->forWrite(),
                            // Every attribute write under ou=people, still under the userPassword deny above.
                            AttributeRule::allow(
                                Subject::dn(self::DELEGATE_DN),
                                Target::subtree('ou=people,dc=foo,dc=bar'),
                            )->forWrite(),
                        )
                        // userPassword ships confidential, so reading it needs a grant on top of the rules above.
                        ->replaceConfidentialAccess(
                            ConfidentialAccessRule::allow(
                                Subject::group('cn=admins,dc=foo,dc=bar'),
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
