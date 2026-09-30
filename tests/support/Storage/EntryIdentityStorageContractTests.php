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

namespace Tests\Support\FreeDSx\Ldap\Storage;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\EntryAlreadyExistsException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\EntryUuidTakenException;
use RuntimeException;

/**
 * @mixin \PHPUnit\Framework\TestCase
 */
trait EntryIdentityStorageContractTests
{
    private const IDENTITY_UUID_A = '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d';

    private const IDENTITY_UUID_B = '5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b';

    public function test_inserting_an_entry_uuid_another_entry_holds_is_refused(): void
    {
        $container = $this->identityContainer();

        $this->expectException(EntryUuidTakenException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $container->get(WriteEntryInterface::class)->insert($this->identified(
            'cn=Bob,dc=foo,dc=bar',
            self::IDENTITY_UUID_A,
        ));
    }

    public function test_inserting_at_a_taken_dn_is_refused_as_existing_whatever_its_entry_uuid(): void
    {
        $container = $this->identityContainer();

        $this->expectException(EntryAlreadyExistsException::class);

        $container->get(WriteEntryInterface::class)->insert($this->identified(
            'cn=Alice,dc=foo,dc=bar',
            self::IDENTITY_UUID_B,
        ));
    }

    public function test_storing_an_entry_uuid_held_at_another_dn_is_refused_and_writes_nothing(): void
    {
        $container = $this->identityContainer();

        try {
            $container->get(WriteEntryInterface::class)->store($this->identified(
                'cn=Bob,dc=foo,dc=bar',
                self::IDENTITY_UUID_A,
            ));
            self::fail('Storing a held entryUUID at another DN should have been refused.');
        } catch (EntryUuidTakenException $e) {
            self::assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }

        self::assertNull($this->identityEntry($container, 'cn=bob,dc=foo,dc=bar'));
        self::assertNotNull($this->identityEntry($container, 'cn=alice,dc=foo,dc=bar'));
    }

    public function test_storing_the_same_entry_uuid_at_its_dn_updates_it(): void
    {
        $container = $this->identityContainer();
        $alice = $this->identified(
            'cn=Alice,dc=foo,dc=bar',
            self::IDENTITY_UUID_A,
        );
        $alice->set(
            'description',
            'updated',
        );

        $container->get(WriteEntryInterface::class)->store($alice);

        self::assertSame(
            'updated',
            $this->identityEntry($container, 'cn=alice,dc=foo,dc=bar')?->get('description')?->firstValue(),
        );
    }

    public function test_storing_a_different_entry_uuid_at_a_dn_replaces_the_entry_and_frees_its_entry_uuid(): void
    {
        $container = $this->identityContainer();
        $writes = $container->get(WriteEntryInterface::class);

        $writes->store($this->identified(
            'cn=Alice,dc=foo,dc=bar',
            self::IDENTITY_UUID_B,
        ));
        $writes->store($this->identified(
            'cn=Bob,dc=foo,dc=bar',
            self::IDENTITY_UUID_A,
        ));

        self::assertSame(
            self::IDENTITY_UUID_B,
            $this->identityEntry($container, 'cn=alice,dc=foo,dc=bar')?->getUuid(),
        );
        self::assertSame(
            self::IDENTITY_UUID_A,
            $this->identityEntry($container, 'cn=bob,dc=foo,dc=bar')?->getUuid(),
        );
    }

    public function test_removing_an_entry_frees_its_entry_uuid(): void
    {
        $container = $this->identityContainer();
        $writes = $container->get(WriteEntryInterface::class);

        $writes->remove(new Dn('cn=alice,dc=foo,dc=bar'));
        $writes->insert($this->identified(
            'cn=Bob,dc=foo,dc=bar',
            self::IDENTITY_UUID_A,
        ));

        self::assertNotNull($this->identityEntry($container, 'cn=bob,dc=foo,dc=bar'));
    }

    public function test_a_renamed_entry_keeps_its_entry_uuid_at_its_new_dn(): void
    {
        $container = $this->identityContainer();
        $writes = $container->get(WriteEntryInterface::class);

        $writes->renameSubtree(
            new Dn('cn=alice,dc=foo,dc=bar'),
            new Dn('cn=Alicia,dc=foo,dc=bar'),
        );
        $writes->store($this->identified(
            'cn=Alicia,dc=foo,dc=bar',
            self::IDENTITY_UUID_A,
        ));

        $this->expectException(EntryUuidTakenException::class);

        $writes->store($this->identified(
            'cn=Alice,dc=foo,dc=bar',
            self::IDENTITY_UUID_A,
        ));
    }

    public function test_an_entry_uuid_claimed_in_a_failed_atomic_block_is_free_afterwards(): void
    {
        $container = $this->identityContainer();
        $writes = $container->get(WriteEntryInterface::class);

        try {
            $container->get(TransactionalWriteInterface::class)->atomic(function () use ($writes): void {
                $writes->store($this->identified(
                    'cn=Bob,dc=foo,dc=bar',
                    self::IDENTITY_UUID_B,
                ));

                throw new RuntimeException('failed part way through');
            });
        } catch (RuntimeException) {
        }

        $writes->insert($this->identified(
            'cn=Carol,dc=foo,dc=bar',
            self::IDENTITY_UUID_B,
        ));

        self::assertNotNull($this->identityEntry($container, 'cn=carol,dc=foo,dc=bar'));
    }

    abstract protected function makeStorageContainer(Entry ...$entries): Container;

    private function identityContainer(): Container
    {
        return $this->makeStorageContainer(
            new Entry(new Dn('dc=foo,dc=bar')),
            $this->identified(
                'cn=Alice,dc=foo,dc=bar',
                self::IDENTITY_UUID_A,
            ),
        );
    }

    private function identified(
        string $dn,
        string $uuid,
    ): Entry {
        return new Entry(
            new Dn($dn),
            new Attribute('cn', (new Dn($dn))->getRdn()->getValue()),
            new Attribute('entryUUID', $uuid),
        );
    }

    private function identityEntry(
        Container $container,
        string $dn,
    ): ?Entry {
        return $container->get(ReadEntryInterface::class)
            ->find(new Dn($dn));
    }
}
