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

namespace Tests\Integration\FreeDSx\Ldap\Ldif;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Import\SeedOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class LdapSeedServerTest extends TestCase
{
    private const SEED_LDIF = <<<LDIF
        dn: dc=example,dc=com
        objectClass: top
        objectClass: domain
        dc: example

        dn: cn=alice,dc=example,dc=com
        objectClass: top
        objectClass: person
        cn: alice
        sn: Anderson
        LDIF;

    private LdapServer $subject;

    private EntryStorageInterface $storage;

    protected function setUp(): void
    {
        $options = TestServerOptions::sqlite();
        $container = Container::forServer($options);

        $this->subject = new LdapServer(
            $options,
            $container,
        );
        $this->storage = $container->get(EntryStorageInterface::class);
    }

    public function test_it_seeds_the_content_records(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        self::assertNotNull($this->storage->find(new Dn('dc=example,dc=com')));
        self::assertNotNull($this->storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_it_refuses_an_entry_that_already_exists(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));
    }

    public function test_it_replaces_an_existing_entry_when_asked(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));
        $uuid = $this->storage->find(new Dn('cn=alice,dc=example,dc=com'))
            ?->get('entryUUID')
            ?->firstValue();

        $this->subject->seed(
            new StringLdifLoader(str_replace('sn: Anderson', 'sn: Replaced', self::SEED_LDIF)),
            (new SeedOptions())->setReplaceExisting(true),
        );

        $alice = $this->storage->find(new Dn('cn=alice,dc=example,dc=com'));
        self::assertNotNull($alice);
        self::assertSame(
            'Replaced',
            $alice->get('sn')?->firstValue(),
        );
        self::assertNotSame(
            $uuid,
            $alice->get('entryUUID')?->firstValue(),
            'An LDIF carrying no entryUUID gives the replacement a new one.',
        );
    }

    public function test_a_replacement_keeps_the_entry_uuid_the_source_supplies(): void
    {
        $withUuid = self::SEED_LDIF . "\nentryUUID: 11111111-2222-4333-8444-555555555555\n";

        $this->subject->seed(new StringLdifLoader($withUuid));
        $this->subject->seed(
            new StringLdifLoader($withUuid),
            (new SeedOptions())->setReplaceExisting(true),
        );

        self::assertSame(
            '11111111-2222-4333-8444-555555555555',
            $this->storage->find(new Dn('cn=alice,dc=example,dc=com'))
                ?->get('entryUUID')
                ?->firstValue(),
        );
    }

    public function test_a_failure_rolls_the_whole_batch_back(): void
    {
        try {
            $this->subject->seedEntries([
                Entry::fromArray('dc=example,dc=com', ['objectClass' => ['top', 'domain'], 'dc' => 'example']),
                Entry::fromArray('cn=alice,dc=example,dc=com', [
                    'objectClass' => ['top', 'person'],
                    'cn' => 'alice',
                    'sn' => 'Anderson',
                ]),
                // Refused as a duplicate, which must take the two before it down with it.
                Entry::fromArray('cn=alice,dc=example,dc=com', [
                    'objectClass' => ['top', 'person'],
                    'cn' => 'alice',
                    'sn' => 'Anderson',
                ]),
            ]);
            self::fail('The duplicate entry should have failed the batch.');
        } catch (OperationException) {
        }

        self::assertNull($this->storage->find(new Dn('dc=example,dc=com')));
        self::assertNull($this->storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }
}
