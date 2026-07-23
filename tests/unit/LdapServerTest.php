<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Ldif\Output\StringLdifOutput;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DumpOptions;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\ReplicaConfig;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class LdapServerTest extends TestCase
{
    private const SEED_LDIF = <<<'LDIF'
        dn: dc=example,dc=com
        objectClass: top
        objectClass: domain
        dc: example

        dn: cn=foo,dc=example,dc=com
        objectClass: top
        objectClass: person
        cn: foo
        sn: Bar
        LDIF;

    private LdapServer $subject;

    private ServerOptions $options;

    private Container $container;

    private ServerRunnerInterface&MockObject $mockServerRunner;

    protected function setUp(): void
    {
        $this->mockServerRunner = $this->createMock(ServerRunnerInterface::class);

        $this->options = (new ServerOptions())
            ->setPort(33389)
            ->setServerRunner($this->mockServerRunner);

        $this->container = Container::forServer($this->options);
        $this->subject = new LdapServer(
            $this->options,
            $this->container,
        );
    }

    public function test_it_should_run_the_server(): void
    {
        $this->mockServerRunner
            ->expects(self::once())
            ->method('run');

        $this->subject->run();
    }

    public function test_run_throws_for_a_forking_replica_on_in_memory_storage(): void
    {
        $this->options
            ->setReplicaConfig(new ReplicaConfig(new ClientOptions()))
            ->setStorageConfig(InMemoryStorageConfig::withEntries());

        $this->expectException(RuntimeException::class);

        $this->subject->run();
    }

    public function test_it_should_get_the_default_options(): void
    {
        self::assertEquals(
            [
                'ip' => '0.0.0.0',
                'port' => 33389,
                'unix_socket' => '/var/run/ldap.socket',
                'transport' => 'tcp',
                'idle_timeout' => 600,
                'require_authentication' => true,
                'allow_anonymous' => false,
                'logger' => null,
                'use_ssl' => false,
                'ssl_cert' => null,
                'ssl_cert_key' => null,
                'ssl_cert_passphrase' => null,
                'min_tls_version' => '1.2',
                'ssl_ciphers' => 'DEFAULT',
                'ssl_validate_cert' => false,
                'ssl_allow_self_signed' => null,
                'ssl_ca_cert' => null,
                'monitor_enabled' => false,
                'monitor_snapshot_path' => null,
                'dse_alt_server' => null,
                'dse_vendor_name' => 'FreeDSx',
                'dse_vendor_version' => null,
                'sasl_mechanisms' => [],
            ],
            $this->subject->getOptions()->toArray(),
        );
    }

    public function test_it_does_not_throw_for_sasl_mechanisms_without_a_sasl_backend(): void
    {
        $this->mockServerRunner->method('run');

        $this->options->setSaslMechanisms(ServerOptions::SASL_PLAIN);

        $this->subject->run();

        $this->expectNotToPerformAssertions();
    }

    public function test_it_should_make_a_proxy_server(): void
    {
        $serverOptions = new ServerOptions();
        $server = LdapServer::makeProxy(
            new ProxyOptions(new ClientOptions(['localhost'])),
            $serverOptions,
        );

        self::assertSame(
            $serverOptions,
            $server->getOptions(),
        );
    }

    public function test_it_should_seed_entries_into_the_configured_storage(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        self::assertNotNull($this->storage()->find(new Dn('dc=example,dc=com')));
        $foo = $this->storage()->find(new Dn('cn=foo,dc=example,dc=com'));
        self::assertNotNull($foo);
        self::assertSame(
            ['Bar'],
            $foo->get('sn')?->getValues(),
        );
    }

    public function test_it_should_stamp_operational_attributes_on_seeded_entries(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $foo = $this->storage()->find(new Dn('cn=foo,dc=example,dc=com'));

        self::assertNotNull($foo);
        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $foo->get('entryUUID')?->getValues()[0] ?? '',
        );
        self::assertSame(
            'person',
            $foo->get('structuralObjectClass')?->getValues()[0],
        );
        self::assertSame(
            '',
            $foo->get('creatorsName')?->getValues()[0],
        );
    }

    public function test_it_should_record_the_creator_dn_when_seeding(): void
    {
        $this->subject->seed(
            new StringLdifLoader(self::SEED_LDIF),
            new Dn('cn=Importer,dc=example,dc=com'),
        );

        self::assertSame(
            'cn=Importer,dc=example,dc=com',
            $this->storage()->find(new Dn('cn=foo,dc=example,dc=com'))?->get('creatorsName')?->getValues()[0],
        );
    }

    public function test_it_should_throw_when_seeding_on_a_proxy_server(): void
    {
        $proxy = LdapServer::makeProxy(new ProxyOptions(new ClientOptions(['localhost'])));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('not available on a proxy server');

        $proxy->seed(new StringLdifLoader(self::SEED_LDIF));
    }

    public function test_it_should_reject_seeding_when_the_ldif_contains_change_records(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('only accepts content records');

        $this->subject->seed(new StringLdifLoader("dn: cn=any,dc=x\nchangetype: delete\n"));
    }

    public function test_it_should_apply_modify_changes_against_the_seeded_storage(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $this->subject->applyChanges(new StringLdifLoader(
            "dn: cn=foo,dc=example,dc=com\nchangetype: modify\nreplace: sn\nsn: Updated\n-\n",
        ));

        self::assertSame(
            ['Updated'],
            $this->storage()->find(new Dn('cn=foo,dc=example,dc=com'))?->get('sn')?->getValues(),
        );
    }

    public function test_it_should_apply_a_delete_change_against_the_seeded_storage(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $this->subject->applyChanges(new StringLdifLoader(
            "dn: cn=foo,dc=example,dc=com\nchangetype: delete\n",
        ));

        self::assertNull($this->storage()->find(new Dn('cn=foo,dc=example,dc=com')));
    }

    public function test_it_should_throw_when_applying_changes_on_a_proxy_server(): void
    {
        $proxy = LdapServer::makeProxy(new ProxyOptions(new ClientOptions(['localhost'])));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('not available on a proxy server');

        $proxy->applyChanges(new StringLdifLoader("dn: cn=x,dc=x\nchangetype: delete\n"));
    }

    public function test_it_should_throw_when_dumping_on_a_proxy_server(): void
    {
        $proxy = LdapServer::makeProxy(new ProxyOptions(new ClientOptions(['localhost'])));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('not available on a proxy server');

        $proxy->dump(new StringLdifOutput());
    }

    public function test_it_should_dump_seeded_entries_to_the_given_output(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $output = new StringLdifOutput();
        $this->subject->dump(
            $output,
            (new DumpOptions())->setBaseDn(new Dn('dc=example,dc=com')),
        );

        $ldif = $output->getLdif();
        self::assertStringStartsWith(
            'version: 1',
            $ldif,
        );
        self::assertStringContainsString(
            'dn: dc=example,dc=com',
            $ldif,
        );
        self::assertStringContainsString(
            'dn: cn=foo,dc=example,dc=com',
            $ldif,
        );
    }

    public function test_dump_seed_round_trip_preserves_entryUUID_and_create_timestamp(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $originalFoo = $this->storage()->find(new Dn('cn=foo,dc=example,dc=com'));
        self::assertNotNull($originalFoo);
        $originalUuid = $originalFoo->get('entryUUID')?->firstValue();
        $originalTimestamp = $originalFoo->get('createTimestamp')?->firstValue();
        self::assertNotNull($originalUuid);
        self::assertNotNull($originalTimestamp);

        $output = new StringLdifOutput();
        $this->subject->dump(
            $output,
            (new DumpOptions())->setBaseDn(new Dn('dc=example,dc=com')),
        );

        $restoreOptions = new ServerOptions();
        $restoreContainer = Container::forServer($restoreOptions);
        (new LdapServer(
            $restoreOptions,
            $restoreContainer,
        ))->seed(new StringLdifLoader($output->getLdif()));

        $restoredFoo = $restoreContainer->get(EntryStorageInterface::class)
            ->find(new Dn('cn=foo,dc=example,dc=com'));
        self::assertNotNull($restoredFoo);
        self::assertSame(
            $originalUuid,
            $restoredFoo->get('entryUUID')?->firstValue(),
        );
        self::assertSame(
            $originalTimestamp,
            $restoredFoo->get('createTimestamp')?->firstValue(),
        );
    }

    public function test_it_should_apply_the_dump_options_filter(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $output = new StringLdifOutput();
        $this->subject->dump(
            $output,
            (new DumpOptions())
                ->setBaseDn(new Dn('dc=example,dc=com'))
                ->setFilter(Filters::equal('objectClass', 'person')),
        );

        self::assertStringContainsString(
            'cn=foo,dc=example,dc=com',
            $output->getLdif(),
        );
        self::assertStringNotContainsString(
            'dn: dc=example,dc=com',
            $output->getLdif(),
        );
    }

    /**
     * The container-built storage the server operates on.
     */
    private function storage(): EntryStorageInterface
    {
        return $this->container->get(EntryStorageInterface::class);
    }
}
