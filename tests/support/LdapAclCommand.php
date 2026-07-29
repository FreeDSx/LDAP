<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\StandardSchemaProvider;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\ServerOptions;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class LdapAclCommand extends Command
{
    use ConsoleOptionsTrait;

    /**
     * A confidential attribute of the operator's own, so the mechanism is covered beyond userPassword.
     */
    public const SECRET_CODE_OID = '1.3.6.1.4.1.99999.1.1';

    public const SECRET_CODE = 'S3CR3T-alice';

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
                new Attribute('objectClass', 'inetOrgPerson', 'extensibleObject'),
                new Attribute('userPassword', $alicePasswordHash),
                new Attribute('secretCode', self::SECRET_CODE),
            ),
        ];

        $network = (new NetworkConfig())
            ->setPort(10389)
            ->setTransport($transport)
            ->setSocketAcceptTimeout(0.1);

        $server = new LdapServer(
            (new ServerOptions(network: $network))
                ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL))
                ->setSchema($this->schemaWithSecretCode())
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
                        )
                        // userPassword ships confidential, so reading it needs a grant on top of the rules above.
                        ->withConfidentialAccess(
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

    /**
     * The standard schema plus an operator-defined confidential attribute.
     */
    private function schemaWithSecretCode(): Schema
    {
        return StandardSchemaProvider::buildCore()->addAttributeType(new AttributeType(
            self::SECRET_CODE_OID,
            ['secretCode'],
            equalityOid: MatchingRuleOid::OID_CASE_EXACT_MATCH,
            syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
            extensions: [
                AttributeType::EXTENSION_CONFIDENTIAL => [AttributeType::EXTENSION_ENABLED_VALUE],
            ],
        ));
    }
}
