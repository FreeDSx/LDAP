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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use PHPUnit\Framework\TestCase;

final class LdapImporterTest extends TestCase
{
    public function test_importEntries_persists_all_entries(): void
    {
        $storage = new InMemoryStorage();
        $importer = new LdapImporter($storage);

        $importer->importEntries([
            new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('dc', 'example'),
            ),
            new Entry(
                new Dn('cn=Alice,dc=example,dc=com'),
                new Attribute('cn', 'Alice'),
            ),
        ]);

        self::assertNotNull($storage->find(new Dn('dc=example,dc=com')));
        self::assertNotNull($storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_importEntries_is_noop_when_empty(): void
    {
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage
            ->expects(self::never())
            ->method('atomic');

        (new LdapImporter($storage))->importEntries([]);
    }

    public function test_importEntries_runs_in_single_atomic_call(): void
    {
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage
            ->expects(self::once())
            ->method('atomic');

        (new LdapImporter($storage))->importEntries([
            new Entry(new Dn('dc=example,dc=com')),
            new Entry(new Dn('cn=Alice,dc=example,dc=com')),
        ]);
    }

    public function test_importEntries_sorts_by_depth_so_input_order_does_not_matter(): void
    {
        $storage = new InMemoryStorage();

        (new LdapImporter($storage))->importEntries([
            new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alice')),
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
        ]);

        self::assertNotNull($storage->find(new Dn('dc=example,dc=com')));
        self::assertNotNull($storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_importEntries_throws_when_parent_is_missing(): void
    {
        $storage = new InMemoryStorage();

        self::expectException(InvalidArgumentException::class);
        self::expectExceptionMessage('Parent entry "dc=example,dc=com" does not exist for "cn=Alice,dc=example,dc=com".');

        (new LdapImporter($storage))->importEntries([
            new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alice')),
        ]);
    }

    public function test_importEntries_accepts_existing_parent_in_pre_seeded_storage(): void
    {
        $storage = new InMemoryStorage([
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
        ]);

        (new LdapImporter($storage))->importEntries([
            new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alice')),
        ]);

        self::assertNotNull($storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_importEntries_ignoreValidation_skips_parent_check(): void
    {
        $storage = new InMemoryStorage();

        (new LdapImporter($storage))->importEntries(
            entries: [
                new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alice')),
            ],
            ignoreValidation: true,
        );

        self::assertNotNull($storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }
}
