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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
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

    public function test_importEntries_handles_empty_input(): void
    {
        $storage = new InMemoryStorage();

        (new LdapImporter($storage))->importEntries([]);

        self::assertNull($storage->find(new Dn('dc=example,dc=com')));
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

    public function test_importEntries_requires_input_in_depth_first_order(): void
    {
        $storage = new InMemoryStorage();

        self::expectException(InvalidArgumentException::class);
        self::expectExceptionMessage('Parent entry "dc=example,dc=com" does not exist for "cn=Alice,dc=example,dc=com".');

        (new LdapImporter($storage))->importEntries([
            new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alice')),
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
        ]);
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

    public function test_importEntries_stamps_operational_attributes_by_default(): void
    {
        $storage = new InMemoryStorage();

        (new LdapImporter($storage))->importEntries([
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
        ]);

        $entry = $storage->find(new Dn('dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $entry->get('entryUUID')?->getValues()[0] ?? '',
        );
    }

    public function test_importEntries_records_the_creator_dn_on_stamped_entries(): void
    {
        $storage = new InMemoryStorage();

        (new LdapImporter($storage))->importEntries(
            entries: [
                new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            ],
            creatorDn: new Dn('cn=Importer,dc=example,dc=com'),
        );

        self::assertSame(
            'cn=Importer,dc=example,dc=com',
            $storage->find(new Dn('dc=example,dc=com'))?->get('creatorsName')?->getValues()[0],
        );
    }

    public function test_importEntries_throws_for_an_invalid_creator_dn(): void
    {
        self::expectException(InvalidArgumentException::class);
        self::expectExceptionMessage('The import creator DN "not a dn" is not a valid DN.');

        (new LdapImporter(new InMemoryStorage()))->importEntries(
            entries: [],
            creatorDn: new Dn('not a dn'),
        );
    }

    public function test_importEntries_rejects_a_schema_violation_in_strict_mode(): void
    {
        $validator = new SchemaValidator(
            (TestServerOptions::defaults())->getSchema(),
            SchemaValidationMode::Strict,
        );

        self::expectException(OperationException::class);

        (new LdapImporter(
            new InMemoryStorage(),
            validator: $validator,
        ))->importEntries([
            new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('cn', 'foo'),
                new Attribute('objectClass', 'top', 'person'),
            ),
        ]);
    }

    public function test_importEntries_allows_a_schema_violation_in_lenient_mode(): void
    {
        $storage = new InMemoryStorage();
        $validator = new SchemaValidator(
            (TestServerOptions::defaults())->getSchema(),
            SchemaValidationMode::Lenient,
        );

        (new LdapImporter(
            $storage,
            validator: $validator,
        ))->importEntries([
            new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('cn', 'foo'),
                new Attribute('objectClass', 'top', 'person'),
            ),
        ]);

        self::assertNotNull($storage->find(new Dn('dc=example,dc=com')));
    }

    public function test_importEntries_ignoreValidation_skips_schema_validation_in_strict_mode(): void
    {
        $storage = new InMemoryStorage();
        $validator = new SchemaValidator(
            (TestServerOptions::defaults())->getSchema(),
            SchemaValidationMode::Strict,
        );

        (new LdapImporter(
            $storage,
            validator: $validator,
        ))->importEntries(
            entries: [
                new Entry(
                    new Dn('dc=example,dc=com'),
                    new Attribute('cn', 'foo'),
                    new Attribute('objectClass', 'top', 'person'),
                ),
            ],
            ignoreValidation: true,
        );

        self::assertNotNull($storage->find(new Dn('dc=example,dc=com')));
    }
}
