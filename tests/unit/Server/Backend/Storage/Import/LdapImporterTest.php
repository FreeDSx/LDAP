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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Import;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class LdapImporterTest extends TestCase
{
    use ServerContainerTrait;

    private InMemoryStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
    }

    public function test_importEntries_persists_all_entries(): void
    {
        $this->importer()->importEntries([
            $this->domain(),
            $this->person('cn=Alice,dc=example,dc=com'),
        ]);

        self::assertNotNull($this->storage->find(new Dn('dc=example,dc=com')));
        self::assertNotNull($this->storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_importEntries_handles_empty_input(): void
    {
        $this->importer()->importEntries([]);

        self::assertNull($this->storage->find(new Dn('dc=example,dc=com')));
    }

    public function test_importEntries_requires_input_in_depth_first_order(): void
    {
        self::expectException(InvalidArgumentException::class);
        self::expectExceptionMessage('Parent entry "dc=example,dc=com" does not exist for "cn=Alice,dc=example,dc=com".');

        $this->importer()->importEntries([
            $this->person('cn=Alice,dc=example,dc=com'),
            $this->domain(),
        ]);
    }

    public function test_importEntries_throws_when_parent_is_missing(): void
    {
        self::expectException(InvalidArgumentException::class);
        self::expectExceptionMessage('Parent entry "dc=example,dc=com" does not exist for "cn=Alice,dc=example,dc=com".');

        $this->importer()->importEntries([
            $this->person('cn=Alice,dc=example,dc=com'),
        ]);
    }

    public function test_importEntries_accepts_existing_parent_in_pre_seeded_storage(): void
    {
        $this->importer()->importEntries([$this->domain()]);
        $this->importer()->importEntries([$this->person('cn=Alice,dc=example,dc=com')]);

        self::assertNotNull($this->storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_importEntries_ignoreValidation_skips_parent_check(): void
    {
        $this->importer()->importEntries(
            entries: [$this->person('cn=Alice,dc=example,dc=com')],
            ignoreValidation: true,
        );

        self::assertNotNull($this->storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_importEntries_stamps_operational_attributes_by_default(): void
    {
        $this->importer()->importEntries([$this->domain()]);

        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $this->storage->find(new Dn('dc=example,dc=com'))?->get('entryUUID')?->firstValue() ?? '',
        );
    }

    public function test_importEntries_keeps_the_operational_attributes_the_source_supplied(): void
    {
        $entry = $this->domain();
        $entry->add('entryUUID', '11111111-2222-4333-8444-555555555555');

        $this->importer()->importEntries([$entry]);

        self::assertSame(
            '11111111-2222-4333-8444-555555555555',
            $this->storage->find(new Dn('dc=example,dc=com'))?->get('entryUUID')?->firstValue(),
        );
    }

    public function test_importEntries_records_the_creator_dn_on_stamped_entries(): void
    {
        $this->importer()->importEntries(
            entries: [$this->domain()],
            creatorDn: new Dn('cn=Importer,dc=example,dc=com'),
        );

        self::assertSame(
            'cn=Importer,dc=example,dc=com',
            $this->storage->find(new Dn('dc=example,dc=com'))?->get('creatorsName')?->firstValue(),
        );
    }

    public function test_importEntries_throws_for_an_invalid_creator_dn(): void
    {
        self::expectException(InvalidArgumentException::class);
        self::expectExceptionMessage('The import creator DN "not a dn" is not a valid DN.');

        $this->importer()->importEntries(
            entries: [],
            creatorDn: new Dn('not a dn'),
        );
    }

    public function test_importEntries_refuses_an_entry_that_already_exists(): void
    {
        $this->importer()->importEntries([$this->domain()]);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->importer()->importEntries([$this->domain()]);
    }

    public function test_importEntries_records_the_counts_once_the_batch_commits(): void
    {
        $logger = new RecordingLogger();

        $this->importerFor(
            $this->storage,
            $this->optionsLogging($logger),
        )->importEntries([
            $this->domain(),
            $this->person('cn=Alice,dc=example,dc=com'),
        ]);

        self::assertSame(
            [ServerEvent::BulkImportCompleted->value],
            $this->loggedEvents($logger),
        );
        self::assertSame(
            2,
            $logger->records[0]['context'][EventContext::ENTRIES_ADDED] ?? null,
        );
    }

    public function test_importEntries_records_each_entry_it_replaced(): void
    {
        $logger = new RecordingLogger();
        $options = $this->optionsLogging($logger);

        $this->importerFor($this->storage, $options)->importEntries([$this->domain()]);
        $logger->records = [];

        $this->importerFor($this->storage, $options)->importEntries(
            entries: [$this->domain()],
            replaceExisting: true,
        );

        self::assertSame(
            [
                ServerEvent::EntryReplaced->value,
                ServerEvent::BulkImportCompleted->value,
            ],
            $this->loggedEvents($logger),
        );
    }

    public function test_importEntries_records_a_failure_rather_than_a_completion(): void
    {
        $logger = new RecordingLogger();
        $options = $this->optionsLogging($logger);

        $this->importerFor($this->storage, $options)->importEntries([$this->domain()]);
        $logger->records = [];

        try {
            $this->importerFor($this->storage, $options)->importEntries([$this->domain()]);
        } catch (OperationException) {
        }

        self::assertSame(
            [ServerEvent::BulkImportFailed->value],
            $this->loggedEvents($logger),
        );
    }

    public function test_importEntries_does_not_mutate_the_entries_it_was_given(): void
    {
        $entry = $this->domain();

        $this->importer()->importEntries([$entry]);

        self::assertNull($entry->get('entryUUID'));
    }

    public function test_importEntries_rejects_a_schema_violation_in_strict_mode(): void
    {
        self::expectException(OperationException::class);

        $this->importerFor(
            $this->storage,
            TestServerOptions::validatedCore(SchemaValidationMode::Strict),
        )->importEntries([$this->schemaViolation()]);
    }

    public function test_importEntries_allows_a_schema_violation_in_lenient_mode(): void
    {
        $this->importerFor(
            $this->storage,
            TestServerOptions::validatedCore(SchemaValidationMode::Lenient),
        )->importEntries([$this->schemaViolation()]);

        self::assertNotNull($this->storage->find(new Dn('dc=example,dc=com')));
    }

    public function test_importEntries_ignoreValidation_relaxes_schema_validation_in_strict_mode(): void
    {
        $this->importerFor(
            $this->storage,
            TestServerOptions::validatedCore(SchemaValidationMode::Strict),
        )->importEntries(
            entries: [$this->schemaViolation()],
            ignoreValidation: true,
        );

        self::assertNotNull($this->storage->find(new Dn('dc=example,dc=com')));
    }

    public function test_importEntries_ignoreValidation_still_rejects_an_invalid_attribute_syntax(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->importerFor(
            $this->storage,
            TestServerOptions::validatedCore(SchemaValidationMode::Strict),
        )->importEntries(
            entries: [
                new Entry(
                    new Dn('dc=example,dc=com'),
                    new Attribute('dc', 'example'),
                    new Attribute('objectClass', 'top', 'domain'),
                    new Attribute('seeAlso', 'not a dn'),
                ),
            ],
            ignoreValidation: true,
        );
    }

    private function optionsLogging(RecordingLogger $logger): ServerOptions
    {
        return TestServerOptions::unvalidatedCore()->setLogger($logger);
    }

    /**
     * @return list<string>
     */
    private function loggedEvents(RecordingLogger $logger): array
    {
        return array_map(
            static fn(array $record): string => $record['message'],
            $logger->records,
        );
    }

    private function importer(): LdapImporter
    {
        return $this->importerFor($this->storage);
    }

    private function importerFor(
        EntryStorageInterface $storage,
        ?ServerOptions $options = null,
    ): LdapImporter {
        return $this->containerFor(
            $storage,
            $options ?? TestServerOptions::unvalidatedCore(),
        )->get(LdapImporter::class);
    }

    private function domain(): Entry
    {
        return new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('dc', 'example'),
            new Attribute('objectClass', 'top', 'domain'),
        );
    }

    private function person(string $dn): Entry
    {
        return new Entry(
            new Dn($dn),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Anderson'),
            new Attribute('objectClass', 'top', 'person'),
        );
    }

    private function schemaViolation(): Entry
    {
        return new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('cn', 'foo'),
            new Attribute('objectClass', 'top', 'person'),
        );
    }
}
