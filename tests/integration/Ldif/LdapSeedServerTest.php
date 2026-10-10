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
use FreeDSx\Ldap\Exception\RecordRefusedException;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
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

    private ReadEntryInterface $storage;

    protected function setUp(): void
    {
        $options = TestServerOptions::sqlite();
        $container = Container::forServer($options);

        $this->subject = new LdapServer(
            $options,
            $container,
        );
        $this->storage = $container->get(ReadEntryInterface::class);
    }

    public function test_it_seeds_the_content_records(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        self::assertNotNull($this->storage->find(new Dn('dc=example,dc=com')));
        self::assertNotNull($this->storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_it_seeds_an_entry_spelled_with_aliases_under_the_primary_names(): void
    {
        $this->subject->seed(new StringLdifLoader(<<<LDIF
            dn: dc=example,dc=com
            objectClass: top
            objectClass: domain
            dc: example

            dn: commonName=bob,dc=example,dc=com
            objectClass: top
            objectClass: person
            commonName: bob
            surname: Builder
            LDIF));

        $bob = $this->storage->find(new Dn('cn=bob,dc=example,dc=com'));

        self::assertNotNull($bob);
        self::assertSame(
            'cn=bob,dc=example,dc=com',
            $bob->getDn()->toString(),
        );
        self::assertSame(
            ['bob'],
            $bob->get('cn')?->getValues(),
        );
        self::assertSame(
            ['Builder'],
            $bob->get('sn')?->getValues(),
        );
    }

    public function test_an_existing_entry_named_by_a_numeric_oid_is_skipped_when_asked(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $this->subject->seed(
            new StringLdifLoader(str_replace(
                ['dn: cn=alice', 'sn: Anderson'],
                ['dn: 2.5.4.3=alice', 'sn: Skipped'],
                self::SEED_LDIF,
            )),
            (new SeedOptions())->setSkipExisting(true),
        );

        self::assertSame(
            'Anderson',
            $this->storage->find(new Dn('cn=alice,dc=example,dc=com'))?->get('sn')?->firstValue(),
        );
    }

    public function test_it_refuses_an_entry_that_already_exists(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));
    }

    public function test_it_leaves_an_existing_entry_untouched_when_asked_to_skip_it(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));
        $uuid = $this->storage->find(new Dn('cn=alice,dc=example,dc=com'))?->getUuid();

        $this->subject->seed(
            new StringLdifLoader(str_replace('sn: Anderson', 'sn: Skipped', self::SEED_LDIF)),
            (new SeedOptions())->setSkipExisting(true),
        );

        $alice = $this->storage->find(new Dn('cn=alice,dc=example,dc=com'));
        self::assertNotNull($alice);
        self::assertSame(
            'Anderson',
            $alice->get('sn')?->firstValue(),
        );
        self::assertSame(
            $uuid,
            $alice->getUuid(),
        );
    }

    public function test_skipping_existing_entries_still_adds_the_new_ones(): void
    {
        $this->subject->seed(new StringLdifLoader(self::SEED_LDIF));

        $this->subject->seed(
            new StringLdifLoader(self::SEED_LDIF . <<<LDIF


                dn: cn=bob,dc=example,dc=com
                objectClass: top
                objectClass: person
                cn: bob
                sn: Builder
                LDIF),
            (new SeedOptions())->setSkipExisting(true),
        );

        self::assertNotNull($this->storage->find(new Dn('cn=bob,dc=example,dc=com')));
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

    public function test_an_entry_refused_by_seeding_names_its_dn_and_ldif_line(): void
    {
        try {
            $this->subject->seed(new StringLdifLoader(self::SEED_LDIF . <<<LDIF


                dn: cn=orphan,ou=missing,dc=example,dc=com
                objectClass: top
                objectClass: person
                cn: orphan
                sn: Orphan
                LDIF));
            self::fail('The entry whose parent is missing should have been refused.');
        } catch (RecordRefusedException $e) {
            self::assertSame(
                'cn=orphan,ou=missing,dc=example,dc=com',
                $e->getDn()->toString(),
            );
            self::assertSame(
                12,
                $e->getLdifLine(),
            );
            self::assertSame(
                ResultCode::NO_SUCH_OBJECT,
                $e->getCode(),
            );
        }
    }

    public function test_a_reference_the_batch_leaves_unresolved_is_not_blamed_on_its_last_entry(): void
    {
        try {
            $this->subject->seed(new StringLdifLoader(self::SEED_LDIF . <<<LDIF


                dn: cn=group,dc=example,dc=com
                objectClass: top
                objectClass: groupOfNames
                cn: group
                member: cn=ghost,dc=example,dc=com

                dn: cn=last,dc=example,dc=com
                objectClass: top
                objectClass: person
                cn: last
                sn: Last
                LDIF));
            self::fail('The unresolved member should have refused the batch.');
        } catch (OperationException $e) {
            self::assertNotInstanceOf(
                RecordRefusedException::class,
                $e,
            );
            self::assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }
    }
}
