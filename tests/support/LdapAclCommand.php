<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;
use FreeDSx\Ldap\Schema\LdifSchemaSource;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\FilterAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
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
     * Carries one attribute per spelled-member group, each denied to that group's members.
     */
    public const SPELLED_TARGET_DN = 'cn=spelled-target,dc=foo,dc=bar';

    /**
     * Names cn=user by the numeric OID of cn.
     */
    public const OID_MEMBER_GROUP_DN = 'cn=blocked-oid,dc=foo,dc=bar';

    /**
     * Names cn=user by an alias of cn.
     */
    public const ALIAS_MEMBER_GROUP_DN = 'cn=blocked-alias,dc=foo,dc=bar';

    /**
     * Names cn=user by the numeric OID of cn through uniqueMember, which is not held as a link.
     */
    public const UNIQUE_MEMBER_GROUP_DN = 'cn=blocked-unique,dc=foo,dc=bar';

    /**
     * Seeded without cn=user, so a test can add it over the wire.
     */
    public const LATE_MEMBER_GROUP_DN = 'cn=blocked-late,dc=foo,dc=bar';

    /**
     * Defines secretCode as confidential; loaded so the harness exercises the same path an operator would.
     */
    private const SECRET_CODE_SCHEMA = __DIR__ . '/../resources/schema/acl-secret-code.ldif';

    private const SEED_LDIF = __DIR__ . '/../resources/seed/acl-seed.ldif';

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

        $network = (new NetworkConfig())
            ->setPort(TestWorker::port())
            ->setTransport($transport)
            ->setSocketAcceptTimeout(0.1);

        $dbPath = TestWorker::path('acl.sqlite');

        foreach ([$dbPath, $dbPath . '-wal', $dbPath . '-shm'] as $path) {
            if (file_exists($path)) {
                unlink($path);
            }
        }

        $serverOptions = (new ServerOptions(
            PdoConfig::forSqlite($dbPath),
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
                            // Only bites if the member value spelled by OID is recognized as cn=user.
                            OperationRule::deny(
                                Subject::group(self::OID_MEMBER_GROUP_DN),
                                Target::dn(self::SPELLED_TARGET_DN),
                                OperationType::Compare,
                            ),
                            OperationRule::allow(
                                Subject::authenticated(),
                                Target::any(),
                                OperationType::Search,
                                OperationType::Compare,
                            ),
                            // A reserved destination, ahead of the rename grant below, so only the DN an entry
                            // lands on can refuse it.
                            OperationRule::deny(
                                Subject::anyone(),
                                Target::dn('cn=reserved,ou=people,dc=foo,dc=bar'),
                                OperationType::ModifyDn,
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
                            // Each only bites if its group's member value, spelled another way, is recognized.
                            AttributeRule::deny(
                                Subject::group(self::OID_MEMBER_GROUP_DN),
                                Target::dn(self::SPELLED_TARGET_DN),
                                'description',
                            )->forRead(),
                            AttributeRule::deny(
                                Subject::group(self::ALIAS_MEMBER_GROUP_DN),
                                Target::dn(self::SPELLED_TARGET_DN),
                                'title',
                            )->forRead(),
                            AttributeRule::deny(
                                Subject::group(self::LATE_MEMBER_GROUP_DN),
                                Target::dn(self::SPELLED_TARGET_DN),
                                'street',
                            )->forRead(),
                            AttributeRule::deny(
                                Subject::group(
                                    self::UNIQUE_MEMBER_GROUP_DN,
                                    'uniqueMember',
                                ),
                                Target::dn(self::SPELLED_TARGET_DN),
                                'postalCode',
                            )->forRead(),
                            // Spelled with an alias, so the rule only bites if rule names are canonicalized.
                            AttributeRule::deny(
                                Subject::anyone(),
                                Target::dn(self::DELEGATE_DN),
                                'surname',
                            )->forRead(),
                            // Built through the public constructor with a mixed-case name, so the rule only bites
                            // if names are normalized wherever a rule is made.
                            new AttributeRule(
                                Effect::Deny,
                                Subject::anyone(),
                                Target::any(),
                                ['TelephoneNumber'],
                                AttributeAccess::Read,
                            ),
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
                        )
                        // The read deny above still leaves the value guessable through a filter, so pair it with this.
                        ->replaceFilterAccess(
                            FilterAccessRule::deny(
                                Subject::anyone(),
                                'telephoneNumber',
                            ),
                        ),
                );

        $container = Container::forServer($serverOptions);
        $server = new LdapServer(
            $serverOptions,
            $container,
        );

        $server->seed(new FileLdifLoader(self::SEED_LDIF));
        $server->run();

        return Command::SUCCESS;
    }
}
