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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqliteFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\TrigramSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryIndexWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeIndexForms;
use FreeDSx\Ldap\Server\Config\Storage\SubstringIndexMode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoStorageFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Pdo\RecordingPdo;
use Tests\Support\FreeDSx\Ldap\Journal\JournalingStorageContractTests;

final class PdoStorageTest extends TestCase
{
    use ServerContainerTrait;

    use JournalingStorageContractTests;

    private WritableStorageBackend $subject;

    private PdoStorage $storage;

    private Entry $alice;

    protected function setUp(): void
    {
        $this->alice = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('userPassword', 'secret'),
        );

        $this->storage = $this->pdoStorage(TestServerOptions::sqlite());
        $this->subject = $this->backendFor($this->storage);
        $this->subject->add(
            new AddCommand(
                new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            ),
            $this->systemContext(),
        );
        $this->subject->add(
            new AddCommand($this->alice),
            $this->context(),
        );
    }

    /**
     * Canonicalizing drops the space in "cn=spaced, dc=..." where LOWER() keeps it, so keying the sort off the
     * lowercased DN rather than lc_dn misses this entry's sidecar rows and sorts it as if the attribute were unset.
     */
    public function test_sorting_keys_off_a_dn_whose_canonical_form_differs_from_its_literal_case(): void
    {
        $this->storage->store(new Entry(
            new Dn('cn=spaced, dc=example,dc=com'),
            new Attribute('cn', 'spaced'),
            new Attribute('sn', 'aaa'),
        ));
        $this->storage->store(new Entry(
            new Dn('cn=plain,dc=example,dc=com'),
            new Attribute('cn', 'plain'),
            new Attribute('sn', 'bbb'),
        ));

        $entries = iterator_to_array($this->storage->list(new StorageListOptions(
            baseDn: new Dn('dc=example,dc=com'),
            subtree: true,
            filter: Filters::present('sn'),
            sortKeys: [new SortKey('sn')],
        ))->entries);

        self::assertSame(
            ['cn=spaced, dc=example,dc=com', 'cn=plain,dc=example,dc=com'],
            array_map(
                static fn(Entry $entry): string => $entry->getDn()->toString(),
                $entries,
            ),
        );
    }

    public function test_searches_differing_only_in_size_limit_share_one_prepared_statement(): void
    {
        $pdo = new RecordingPdo('sqlite::memory:');
        PdoStorage::initialize(
            $pdo,
            new SqliteDialect(),
        );
        $storage = $this->storageOver($pdo);
        foreach (range(1, 3) as $i) {
            $storage->store(new Entry(
                new Dn("cn=e{$i},dc=example,dc=com"),
                new Attribute('cn', "e{$i}"),
                new Attribute('sn', 'x'),
            ));
        }

        foreach ([1, 2, 3] as $sizeLimit) {
            iterator_count($storage->list(new StorageListOptions(
                baseDn: new Dn('dc=example,dc=com'),
                subtree: true,
                filter: Filters::equal('sn', 'x'),
                sizeLimit: $sizeLimit,
            ))->entries);
        }

        self::assertCount(
            1,
            $pdo->preparedMatching('LIMIT ?'),
        );
    }

    public function test_a_projection_that_materializes_nothing_still_yields_the_dns(): void
    {
        $this->storage->store(new Entry(
            new Dn('cn=bob,dc=example,dc=com'),
            new Attribute('cn', 'bob'),
            new Attribute('sn', 'x'),
        ));

        $entries = iterator_to_array($this->storage->list(new StorageListOptions(
            baseDn: new Dn('dc=example,dc=com'),
            subtree: true,
            filter: Filters::equal('sn', 'x'),
            attributes: [],
        ))->entries);

        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            'cn=bob,dc=example,dc=com',
            $entries[0]->getDn()->toString(),
        );
        self::assertSame(
            [],
            $entries[0]->toArray(),
        );
    }

    public function test_remove_all_deletes_every_given_entry_and_ignores_missing_ones(): void
    {
        foreach (range(1, 3) as $i) {
            $this->storage->store(new Entry(
                new Dn("cn=e{$i},dc=example,dc=com"),
                new Attribute('cn', "e{$i}"),
            ));
        }

        $this->storage->removeAll([
            (new Dn('cn=e1,dc=example,dc=com'))->normalize(),
            (new Dn('cn=gone,dc=example,dc=com'))->normalize(),
            (new Dn('cn=e3,dc=example,dc=com'))->normalize(),
        ]);

        self::assertFalse($this->storage->exists(new Dn('cn=e1,dc=example,dc=com')));
        self::assertTrue($this->storage->exists(new Dn('cn=e2,dc=example,dc=com')));
        self::assertFalse($this->storage->exists(new Dn('cn=e3,dc=example,dc=com')));
    }

    public function test_remove_all_spans_more_entries_than_one_batch(): void
    {
        $dns = [];
        $this->storage->atomic(function () use (&$dns): void {
            foreach (range(1, 1200) as $i) {
                $dn = new Dn("cn=b{$i},dc=example,dc=com");
                $this->storage->store(new Entry(
                    $dn,
                    new Attribute('cn', "b{$i}"),
                ));
                $dns[] = $dn->normalize();
            }
        });

        $this->storage->removeAll($dns);

        self::assertFalse($this->storage->exists(new Dn('cn=b1,dc=example,dc=com')));
        self::assertFalse($this->storage->exists(new Dn('cn=b600,dc=example,dc=com')));
        self::assertFalse($this->storage->exists(new Dn('cn=b1200,dc=example,dc=com')));
    }

    public function test_a_modified_value_stops_matching_its_old_value_and_starts_matching_the_new(): void
    {
        $dn = new Dn('cn=drift,dc=example,dc=com');
        $this->storage->store(new Entry(
            $dn,
            new Attribute('cn', 'drift'),
            new Attribute('sn', 'before'),
            new Attribute('description', 'untouched'),
        ));

        $this->storage->store(new Entry(
            $dn,
            new Attribute('cn', 'drift'),
            new Attribute('sn', 'after'),
            new Attribute('description', 'untouched'),
        ));

        self::assertSame(
            [],
            $this->dnsMatching(Filters::equal('sn', 'before')),
        );
        self::assertSame(
            ['cn=drift,dc=example,dc=com'],
            $this->dnsMatching(Filters::equal('sn', 'after')),
        );
        // An attribute nobody touched must survive the partial rewrite.
        self::assertSame(
            ['cn=drift,dc=example,dc=com'],
            $this->dnsMatching(Filters::equal('description', 'untouched')),
        );
    }

    public function test_a_removed_attribute_stops_matching_after_a_modify(): void
    {
        $dn = new Dn('cn=shrink,dc=example,dc=com');
        $this->storage->store(new Entry(
            $dn,
            new Attribute('cn', 'shrink'),
            new Attribute('sn', 'gone'),
        ));

        $this->storage->store(new Entry(
            $dn,
            new Attribute('cn', 'shrink'),
        ));

        self::assertSame(
            [],
            $this->dnsMatching(Filters::equal('sn', 'gone')),
        );
        self::assertSame(
            [],
            $this->dnsMatching(Filters::present('sn')),
        );
    }

    /**
     * The SQL predicate has to answer the attribute's own EQUALITY rule, not a case-folded comparison.
     *
     * @param non-empty-string $attribute
     */
    #[DataProvider('rewrittenSpellingProvider')]
    public function test_a_value_matches_an_assertion_spelled_differently_under_its_matching_rule(
        string $attribute,
        string $stored,
        string $asserted,
    ): void {
        $this->storage->store(new Entry(
            new Dn('cn=spelling,dc=example,dc=com'),
            new Attribute('cn', 'spelling'),
            new Attribute($attribute, $stored),
        ));

        self::assertContains(
            'cn=spelling,dc=example,dc=com',
            $this->dnsMatching(Filters::equal($attribute, $asserted)),
        );
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function rewrittenSpellingProvider(): iterable
    {
        yield 'distinguishedNameMatch ignores RDN spacing and case' => [
            'member',
            'CN=Alice, DC=Example, DC=Com',
            'cn=alice,dc=example,dc=com',
        ];
        yield 'uniqueMemberMatch ignores RDN spacing and case' => [
            'uniqueMember',
            'CN=Alice, DC=Example, DC=Com',
            'cn=alice,dc=example,dc=com',
        ];
        yield 'telephoneNumberMatch ignores hyphens and spaces' => [
            'telephoneNumber',
            '+1-408-555-1212',
            '+1 408 555 1212',
        ];
        yield 'numericStringMatch ignores spaces' => [
            'x121Address',
            '1111 2222',
            '11112222',
        ];
    }

    /**
     * Its only stored attribute type lives in the password policy schema, so this one needs both sources merged.
     */
    public function test_a_generalized_time_value_matches_an_assertion_naming_the_same_instant(): void
    {
        // The policy schema is added for pwdChangedTime, whose syntax decides how the value is indexed.
        $options = TestServerOptions::sqlite();
        $options->getSchemaConfig()
            ->addSource(SchemaResource::PasswordPolicy);

        $storage = $this->pdoStorage($options);

        $storage->store(new Entry(
            new Dn('cn=stamped,dc=example,dc=com'),
            new Attribute('cn', 'stamped'),
            new Attribute('pwdChangedTime', '20260101070000-0500'),
        ));

        $entries = iterator_to_array($storage->list(new StorageListOptions(
            baseDn: new Dn('dc=example,dc=com'),
            subtree: true,
            filter: Filters::equal('pwdChangedTime', '20260101120000Z'),
        ))->entries);

        self::assertCount(1, $entries);
    }

    public function test_initialize_creates_the_baseline_schema(): void
    {
        $pdo = new PDO('sqlite::memory:');

        PdoStorage::initialize(
            $pdo,
            new SqliteDialect(),
        );
        // Re-running must be a no-op (the baseline is idempotent).
        PdoStorage::initialize(
            $pdo,
            new SqliteDialect(),
        );

        self::assertSame(
            [
                'entries',
                'entry_attribute_values',
                'ldap_change_journal',
                'ldap_change_journal_seq',
                'ldap_replica_pwpolicy_state',
                'ldap_schema_version',
            ],
            $this->tableNames($pdo),
        );
    }

    public function test_schema_ddl_exports_the_sqlite_baseline(): void
    {
        $ddl = PdoStorage::schemaDdl(new SqliteDialect());

        self::assertStringContainsString(
            'CREATE TABLE IF NOT EXISTS entries',
            $ddl,
        );
        self::assertStringContainsString(
            'ldap_change_journal',
            $ddl,
        );
    }

    public function test_schema_ddl_exports_the_mysql_baseline(): void
    {
        $ddl = PdoStorage::schemaDdl(new MysqlDialect());

        self::assertStringContainsString(
            'CREATE TABLE IF NOT EXISTS entries',
            $ddl,
        );
        self::assertStringContainsString(
            'ENGINE=InnoDB',
            $ddl,
        );
    }

    public function test_initialize_with_a_substring_index_creates_its_table(): void
    {
        $pdo = new PDO('sqlite::memory:');

        PdoStorage::initialize(
            $pdo,
            new SqliteDialect(),
            new TrigramSubstringIndex(),
        );

        self::assertContains(
            'entry_attribute_trigrams',
            $this->tableNames($pdo),
        );
    }

    public function test_store_writes_trigram_rows_for_indexed_attributes(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $index = new TrigramSubstringIndex();
        PdoStorage::initialize(
            $pdo,
            new SqliteDialect(),
            $index,
        );

        $provider = new SharedPdoConnectionProvider(
            $pdo,
            fn(): PDO => $pdo,
        );
        $storage = $this->fromContainer(
            PdoStorageFactory::class,
            options: TestServerOptions::forStorage(
                PdoConfig::forSqlite(':memory:')
                    ->setSubstringIndexMode(SubstringIndexMode::Trigram),
            ),
        )->storageOn($provider);
        $storage->store(new Entry(
            new Dn('cn=Smith,dc=example,dc=com'),
            new Attribute('cn', 'Smith'),
        ));

        $count = $pdo->query(
            "SELECT COUNT(*) FROM entry_attribute_trigrams WHERE trigram = 'smi'",
        );
        self::assertNotFalse($count);
        self::assertSame(
            1,
            (int) $count->fetchColumn(),
        );
    }

    public function test_composed_and_streams_off_a_leaf_and_php_verifies_the_rest(): void
    {
        $this->subject->add(
            new AddCommand(new Entry(
                new Dn('cn=bob,dc=example,dc=com'),
                new Attribute('cn', 'bob'),
                new Attribute('sn', 'common'),
                new Attribute('objectClass', 'person'),
            )),
            $this->context(),
        );
        $this->subject->add(
            new AddCommand(new Entry(
                new Dn('cn=carol,dc=example,dc=com'),
                new Attribute('cn', 'carol'),
                new Attribute('sn', 'common'),
                new Attribute('objectClass', 'device'),
            )),
            $this->context(),
        );

        // sn=common matches both; the AND drives off a leaf and PHP verifies the rest, so carol (objectClass=device) fails
        // the objectClass=person branch and is excluded.
        self::assertSame(
            ['cn=bob,dc=example,dc=com'],
            $this->searchDns(Filters::and(
                Filters::equal('sn', 'common'),
                Filters::equal('objectClass', 'person'),
            )),
        );
    }

    public function test_composed_and_with_no_matching_leaf_returns_nothing(): void
    {
        self::assertSame(
            [],
            $this->searchDns(Filters::and(
                Filters::equal('objectClass', 'person'),
                Filters::equal('cn', 'nobody'),
            )),
        );
    }

    public function test_infix_search_finds_matches_and_rejects_trigram_over_selection(): void
    {
        $this->subject->add(
            new AddCommand(new Entry(
                new Dn('uid=match,dc=example,dc=com'),
                new Attribute('uid', 'match'),
                new Attribute('cn', 'blacksmith'),
            )),
            $this->context(),
        );
        $this->subject->add(
            new AddCommand(new Entry(
                new Dn('uid=scatter,dc=example,dc=com'),
                new Attribute('uid', 'scatter'),
                new Attribute('cn', 'smi mit ith'),
            )),
            $this->context(),
        );

        self::assertSame(
            ['uid=match,dc=example,dc=com'],
            $this->searchDns(Filters::contains('cn', 'smith')),
        );
    }

    public function test_disabling_initialize_skips_schema_creation(): void
    {
        // A named shared-cache in-memory database, so a probe connection sees the same schema.
        $dsn = 'file:freedsx_init_off?mode=memory&cache=shared';

        // Hold the storage's connection open so the shared in-memory database survives the probe read.
        $storage = $this->pdoStorage(TestServerOptions::forStorage(
            PdoConfig::forSqlite($dsn)
                ->setInitializeSchema(false),
        ));

        $probe = new PDO(
            'sqlite:' . $dsn,
            null,
            null,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
        );

        self::assertNotContains(
            'entries',
            $this->tableNames($probe),
        );
        unset($storage);
    }

    public function test_schema_version_is_a_positive_integer(): void
    {
        self::assertGreaterThanOrEqual(
            1,
            PdoStorage::SCHEMA_VERSION,
        );
    }

    public function test_get_returns_entry_by_dn(): void
    {
        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $entry->getDn()->toString(),
        );
    }

    public function test_get_is_case_insensitive(): void
    {
        $entry = $this->subject->get(new Dn('CN=ALICE,DC=EXAMPLE,DC=COM'));

        self::assertNotNull($entry);
    }

    public function test_get_returns_null_for_missing_dn(): void
    {
        self::assertNull($this->subject->get(new Dn('cn=Charlie,dc=example,dc=com')));
    }

    public function test_get_on_empty_database_returns_null(): void
    {
        $storage = $this->pdoStorage(TestServerOptions::sqlite());
        $backend = $this->backendFor($storage);

        self::assertNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_add_persists_entry(): void
    {
        $entry = new Entry(new Dn('cn=Persistent,dc=example,dc=com'), new Attribute('cn', 'Persistent'));
        $this->subject->add(
            new AddCommand($entry),
            $this->context(),
        );

        self::assertNotNull($this->subject->get(new Dn('cn=Persistent,dc=example,dc=com')));
    }

    public function test_delete_removes_entry(): void
    {
        $this->subject->delete(
            new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')),
            $this->context(),
        );

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_list_single_level_returns_direct_children_only(): void
    {
        $grandchild = new Entry(new Dn('cn=Sub,cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $this->subject->add(
            new AddCommand($grandchild),
            $this->context(),
        );

        $request = (new SearchRequest(new AndFilter()))
            ->base('dc=example,dc=com')
            ->useSingleLevelScope();
        $results = iterator_to_array($this->subject->search(
            $request,
            SubentryVisibility::All,
        )->entries);

        self::assertCount(1, $results);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $results[0]->getDn()->toString(),
        );
    }

    public function test_list_recursive_includes_base_and_descendants(): void
    {
        $grandchild = new Entry(new Dn('cn=Sub,cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $this->subject->add(
            new AddCommand($grandchild),
            $this->context(),
        );

        $request = (new SearchRequest(new AndFilter()))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        $results = iterator_to_array($this->subject->search(
            $request,
            SubentryVisibility::All,
        )->entries);

        $dns = array_map(
            static fn(Entry $entry): string => $entry->getDn()->toString(),
            $results,
        );

        self::assertContains(
            'dc=example,dc=com',
            $dns,
        );
        self::assertContains(
            'cn=Alice,dc=example,dc=com',
            $dns,
        );
        self::assertContains(
            'cn=Sub,cn=Alice,dc=example,dc=com',
            $dns,
        );
        self::assertCount(
            3,
            $results,
        );
    }

    public function test_list_from_root_returns_all_entries(): void
    {
        // Test the storage interface directly with an empty base DN (root listing).
        // WritableStorageBackend requires the base DN to exist, so bypass it here.
        $results = iterator_to_array($this->storage->list(StorageListOptions::matchAll(new Dn(''), true))->entries);

        self::assertCount(2, $results);
    }

    public function test_list_materializes_only_the_allowed_base_attributes(): void
    {
        $this->storage->store(new Entry(
            new Dn('cn=narrow,dc=example,dc=com'),
            new Attribute('cn', 'narrow'),
            new Attribute('cn;lang-en', 'Narrow EN'),
            new Attribute('sn', 'Surname'),
            new Attribute('mail', 'narrow@example.com'),
        ));

        $narrow = $this->firstByDn(
            $this->storage->list(new StorageListOptions(
                baseDn: new Dn(''),
                subtree: true,
                filter: new AndFilter(),
                attributes: ['cn'],
            ))->entries,
            'cn=narrow,dc=example,dc=com',
        );

        self::assertNotNull($narrow);
        // Only the allowed base name is built; its option subtype rides along, sn and mail are skipped.
        self::assertSame(
            ['cn', 'cn;lang-en'],
            array_map(
                static fn(Attribute $attribute): string => $attribute->getDescription(),
                $narrow->getAttributes(),
            ),
        );
    }

    public function test_list_with_null_attributes_materializes_every_attribute(): void
    {
        $this->storage->store(new Entry(
            new Dn('cn=full,dc=example,dc=com'),
            new Attribute('cn', 'full'),
            new Attribute('sn', 'Surname'),
            new Attribute('mail', 'full@example.com'),
        ));

        $full = $this->firstByDn(
            $this->storage->list(new StorageListOptions(
                baseDn: new Dn(''),
                subtree: true,
                filter: new AndFilter(),
            ))->entries,
            'cn=full,dc=example,dc=com',
        );

        self::assertNotNull($full);
        self::assertSame(
            ['cn', 'sn', 'mail'],
            array_map(
                static fn(Attribute $attribute): string => $attribute->getDescription(),
                $full->getAttributes(),
            ),
        );
    }

    public function test_interleaved_lists_do_not_share_cursor_state(): void
    {
        $this->subject->add(
            new AddCommand(
                new Entry(new Dn('cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Bob')),
            ),
            $this->context(),
        );
        $this->subject->add(
            new AddCommand(
                new Entry(new Dn('cn=Carol,dc=example,dc=com'), new Attribute('cn', 'Carol')),
            ),
            $this->context(),
        );

        $outerIterator = $this->storage->list(StorageListOptions::matchAll(
            new Dn('dc=example,dc=com'),
            true,
        ))->entries;

        $outerIterator->current();
        $outerIterator->next();

        $inner = iterator_to_array($this->storage->list(StorageListOptions::matchAll(
            new Dn('dc=example,dc=com'),
            true,
        ))->entries);

        $remaining = [];
        while ($outerIterator->valid()) {
            $remaining[] = $outerIterator->current();
            $outerIterator->next();
        }

        self::assertCount(4, $inner);
        // Outer yielded 1 entry before the inner list; the remaining 3 must still come through.
        self::assertCount(3, $remaining);
    }

    public function test_has_children_returns_true_when_children_exist(): void
    {
        self::assertTrue($this->storage->hasChildren(new Dn('dc=example,dc=com')));
    }

    public function test_has_children_returns_false_for_leaf_entry(): void
    {
        self::assertFalse($this->storage->hasChildren(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_attributes_round_trip_through_storage(): void
    {
        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertSame(['Alice'], $entry->get('cn')?->getValues());
        self::assertSame(['secret'], $entry->get('userPassword')?->getValues());
    }

    public function test_attribute_options_round_trip_through_storage(): void
    {
        $dn = new Dn('uid=tagged,dc=example,dc=com');
        $this->subject->add(
            new AddCommand(
                new Entry(
                    $dn,
                    new Attribute('uid', 'tagged'),
                    new Attribute('cn', 'Common'),
                    new Attribute('cn;lang-en', 'English'),
                    new Attribute('userCertificate;binary', 'CERTDATA'),
                ),
            ),
            $this->context(),
        );

        $entry = $this->subject->get($dn);

        self::assertNotNull($entry);
        self::assertSame(
            ['Common'],
            $entry->get(new Attribute('cn'), true)?->getValues(),
        );
        self::assertSame(
            ['English'],
            $entry->get(new Attribute('cn;lang-en'), true)?->getValues(),
        );
        self::assertSame(
            ['CERTDATA'],
            $entry->get(new Attribute('userCertificate;binary'), true)?->getValues(),
        );
    }

    public function test_option_bearing_equality_filter_matches_only_the_subtype(): void
    {
        $this->subject->add(
            new AddCommand(
                new Entry(
                    new Dn('uid=tagged,dc=example,dc=com'),
                    new Attribute('uid', 'tagged'),
                    new Attribute('cn;lang-en', 'shared'),
                ),
            ),
            $this->context(),
        );
        $this->subject->add(
            new AddCommand(
                new Entry(
                    new Dn('uid=plain,dc=example,dc=com'),
                    new Attribute('uid', 'plain'),
                    new Attribute('cn', 'shared'),
                ),
            ),
            $this->context(),
        );

        self::assertSame(
            ['uid=tagged,dc=example,dc=com'],
            $this->searchDns(Filters::equal('cn;lang-en', 'shared')),
        );
        self::assertEqualsCanonicalizing(
            ['uid=tagged,dc=example,dc=com', 'uid=plain,dc=example,dc=com'],
            $this->searchDns(Filters::equal('cn', 'shared')),
        );
    }

    public function test_attribute_name_casing_is_preserved_on_round_trip(): void
    {
        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertNotNull($entry);

        $names = [];
        foreach ($entry->getAttributes() as $attribute) {
            $names[] = $attribute->getName();
        }

        self::assertContains(
            'userPassword',
            $names,
        );
        self::assertNotContains(
            'userpassword',
            $names,
        );
    }

    public function test_search_matches_mixed_case_attribute_via_lowercase_filter(): void
    {
        $request = (new SearchRequest(Filters::equal('userpassword', 'secret')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();

        $results = iterator_to_array($this->subject->search(
            $request,
            SubentryVisibility::All,
        )->entries);

        self::assertCount(1, $results);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $results[0]->getDn()->toString(),
        );
    }

    public function test_search_inexact_filter_trips_lookthrough_limit(): void
    {
        $storage = $this->pdoStorage(TestServerOptions::sqlite());
        $backend = $this->backendFor(
            $storage,
            TestServerOptions::unvalidatedCore()
                ->setMaxSearchLookthrough(2),
        );
        $backend->add(
            new AddCommand(new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'))),
            $this->systemContext(),
        );
        foreach (['Ann', 'Bob', 'Cyd'] as $cn) {
            $backend->add(
                new AddCommand(new Entry(new Dn("cn={$cn},dc=example,dc=com"), new Attribute('cn', $cn))),
                $this->context(),
            );
        }

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $request = (new SearchRequest(Filters::endsWith('cn', 'x')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        iterator_to_array($backend->search(
            $request,
            SubentryVisibility::All,
        )->entries);
    }

    public function test_search_exact_filter_is_not_subject_to_lookthrough(): void
    {
        $storage = $this->pdoStorage(TestServerOptions::sqlite());
        $backend = $this->backendFor(
            $storage,
            TestServerOptions::unvalidatedCore()
                ->setMaxSearchLookthrough(1),
        );
        $backend->add(
            new AddCommand(new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'))),
            $this->systemContext(),
        );
        foreach (['Ann', 'Bob', 'Cyd'] as $cn) {
            $backend->add(
                new AddCommand(new Entry(new Dn("cn={$cn},dc=example,dc=com"), new Attribute('cn', $cn))),
                $this->context(),
            );
        }

        $request = (new SearchRequest(Filters::equal('cn', 'Ann')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();

        self::assertCount(
            1,
            iterator_to_array($backend->search(
                $request,
                SubentryVisibility::All,
            )->entries),
        );
    }

    public function test_search_exact_filter_bounds_transfer_at_lookthrough(): void
    {
        $storage = $this->pdoStorage(TestServerOptions::sqlite());
        $backend = $this->backendFor(
            $storage,
            TestServerOptions::unvalidatedCore()
                ->setMaxSearchLookthrough(2),
        );
        $backend->add(
            new AddCommand(new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'))),
            $this->systemContext(),
        );
        foreach (['Ann', 'Bob', 'Cyd', 'Dan', 'Eve'] as $cn) {
            $backend->add(
                new AddCommand(new Entry(
                    new Dn("cn={$cn},dc=example,dc=com"),
                    new Attribute('cn', $cn),
                    new Attribute('st', 'dup'),
                )),
                $this->context(),
            );
        }

        $request = (new SearchRequest(Filters::equal('st', 'dup')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();

        self::assertCount(
            3,
            iterator_to_array($backend->search(
                $request,
                SubentryVisibility::All,
            )->entries),
        );
    }

    public function test_atomic_rolls_back_on_exception(): void
    {
        $threw = false;

        try {
            $this->storage->atomic(function ($storage): void {
                $storage->store(new Entry(
                    new Dn('cn=Rollback,dc=example,dc=com'),
                    new Attribute('cn', 'Rollback'),
                ));
                throw new \RuntimeException('intentional');
            });
        } catch (\RuntimeException) {
            $threw = true;
        }

        self::assertTrue($threw);
        self::assertNull($this->storage->find(new Dn('cn=rollback,dc=example,dc=com')));
    }

    public function test_atomic_commits_on_success(): void
    {
        $this->storage->atomic(function ($storage): void {
            $storage->store(new Entry(
                new Dn('cn=Committed,dc=example,dc=com'),
                new Attribute('cn', 'Committed'),
            ));
        });

        self::assertNotNull($this->storage->find(new Dn('cn=committed,dc=example,dc=com')));
    }

    public function test_atomic_txDepth_is_not_corrupted_when_beginTransaction_fails(): void
    {
        /** @var PDO&MockObject $mockPdo */
        $mockPdo = $this->createMock(PDO::class);

        $beginTransactionCalls = 0;
        $mockPdo->method('exec')
            ->willReturnCallback(static function (string $sql) use (&$beginTransactionCalls): int {
                if ($sql === 'BEGIN IMMEDIATE') {
                    if (++$beginTransactionCalls === 1) {
                        throw new RuntimeException('DB connection error');
                    }
                }

                return 0;
            });

        $storage = $this->storageOver($mockPdo);

        // First call: BEGIN IMMEDIATE throws; txDepth must recover to 0.
        try {
            $storage->atomic(fn() => null);
            self::fail('Expected RuntimeException was not thrown.');
        } catch (RuntimeException $e) {
            self::assertSame('DB connection error', $e->getMessage());
        }

        // Second call: txDepth is 0, so BEGIN IMMEDIATE must be issued again (not SAVEPOINT).
        // A corrupted txDepth of 1 would issue SAVEPOINT sp_1 here instead.
        $storage->atomic(fn() => null);

        self::assertSame(2, $beginTransactionCalls);
    }

    public function test_atomic_savepoint_failure_preserves_original_exception(): void
    {
        /** @var PDO&MockObject $mockPdo */
        $mockPdo = $this->createMock(PDO::class);
        $mockPdo->method('beginTransaction')->willReturn(true);
        $mockPdo->method('inTransaction')->willReturn(true);
        $mockPdo->method('rollBack')->willReturn(true);

        $execSqlCalls = [];
        $mockPdo->method('exec')
            ->willReturnCallback(static function (string $sql) use (&$execSqlCalls): int {
                $execSqlCalls[] = $sql;
                if (str_contains($sql, 'SAVEPOINT sp_1') && !str_contains($sql, 'ROLLBACK') && !str_contains($sql, 'RELEASE')) {
                    throw new RuntimeException('savepoint error');
                }

                return 0;
            });

        $storage = $this->storageOver($mockPdo);

        try {
            $storage->atomic(function ($storage): void {
                $storage->atomic(fn() => null);
            });
            self::fail('Expected RuntimeException was not thrown.');
        } catch (RuntimeException $e) {
            self::assertSame(
                'savepoint error',
                $e->getMessage(),
            );
        }

        self::assertEmpty(
            array_filter($execSqlCalls, fn(string $s) => str_contains($s, 'ROLLBACK TO SAVEPOINT')),
            'ROLLBACK TO SAVEPOINT must not be attempted when SAVEPOINT creation itself failed.',
        );
    }

    public function test_atomic_savepoint_failure_rolls_back_outer_transaction_when_caught(): void
    {
        /** @var PDO&MockObject $mockPdo */
        $mockPdo = $this->createMock(PDO::class);

        $commitCalls = 0;
        $rollBackCalls = 0;
        $mockPdo->method('exec')
            ->willReturnCallback(static function (string $sql) use (&$commitCalls, &$rollBackCalls): int {
                if ($sql === 'COMMIT') {
                    $commitCalls++;
                } elseif ($sql === 'ROLLBACK') {
                    $rollBackCalls++;
                } elseif (str_contains($sql, 'SAVEPOINT sp_1') && !str_contains($sql, 'ROLLBACK') && !str_contains($sql, 'RELEASE')) {
                    throw new RuntimeException('savepoint error');
                }

                return 0;
            });

        $storage = $this->storageOver($mockPdo);

        $storage->atomic(function ($storage): void {
            try {
                $storage->atomic(fn() => null);
            } catch (RuntimeException) {
                // Caller swallows the inner failure; outer must still abort.
            }
        });

        self::assertSame(
            0,
            $commitCalls,
            'Outer transaction must not commit after a nested savepoint creation failed.',
        );
        self::assertSame(
            1,
            $rollBackCalls,
            'Outer transaction must rollback when its broken flag is set.',
        );
    }

    public function test_atomic_broken_flag_resets_between_unrelated_top_level_transactions(): void
    {
        /** @var PDO&MockObject $mockPdo */
        $mockPdo = $this->createMock(PDO::class);
        $mockPdo->method('exec')
            ->willReturnCallback(static function (string $sql): int {
                if (str_contains($sql, 'SAVEPOINT sp_1') && !str_contains($sql, 'ROLLBACK') && !str_contains($sql, 'RELEASE')) {
                    throw new RuntimeException('savepoint error');
                }

                return 0;
            });

        $storage = $this->storageOver($mockPdo);

        $storage->atomic(function ($storage): void {
            try {
                $storage->atomic(fn() => null);
            } catch (RuntimeException) {
            }
        });

        $commitCalls = 0;
        $mockPdo = $this->createMock(PDO::class);
        $mockPdo->method('exec')
            ->willReturnCallback(static function (string $sql) use (&$commitCalls): int {
                if ($sql === 'COMMIT') {
                    $commitCalls++;
                }

                return 0;
            });

        $storage = $this->storageOver($mockPdo);

        $storage->atomic(fn() => null);

        self::assertSame(
            1,
            $commitCalls,
            'A fresh top-level transaction must commit normally; the broken flag must not leak.',
        );
    }

    public function test_find_throws_when_entry_attributes_blob_is_corrupted(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $dialect = new SqliteDialect();
        PdoStorage::initialize($pdo, $dialect);
        $pdo->exec(
            "INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes) VALUES "
            . "('cn=corrupt,dc=example,dc=com', 'cn=Corrupt,dc=example,dc=com', 'dc=example,dc=com', 'NOT_VALID_BLOB')",
        );

        $storage = $this->storageOver($pdo);

        $this->expectException(StorageIoException::class);

        $storage->find(new Dn('cn=corrupt,dc=example,dc=com'));
    }

    public function test_list_throws_when_entry_attributes_blob_is_corrupted(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $dialect = new SqliteDialect();
        PdoStorage::initialize($pdo, $dialect);
        $validBlob = serialize(['cn' => ['Valid']]);
        $pdo->exec(
            "INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes) VALUES "
            . "('cn=valid,dc=example,dc=com', 'cn=Valid,dc=example,dc=com', 'dc=example,dc=com', '{$validBlob}')",
        );
        $pdo->exec(
            "INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes) VALUES "
            . "('cn=corrupt,dc=example,dc=com', 'cn=Corrupt,dc=example,dc=com', 'dc=example,dc=com', 'NOT_VALID_BLOB')",
        );

        $storage = $this->storageOver($pdo);

        $this->expectException(StorageIoException::class);

        iterator_to_array(
            $storage->list(StorageListOptions::matchAll(new Dn('dc=example,dc=com'), false))->entries,
        );
    }

    public function test_store_throws_dn_too_long_when_dn_exceeds_dialect_max(): void
    {
        $storage = $this->createPdoStorageWithMaxDnLength(10);

        $entry = new Entry(
            new Dn('cn=VeryLongNameThatExceedsTheLimit,dc=example,dc=com'),
            new Attribute('cn', 'VeryLongNameThatExceedsTheLimit'),
        );

        try {
            $storage->store($entry);
            self::fail('Expected DnTooLongException was not thrown.');
        } catch (DnTooLongException $e) {
            self::assertStringContainsString(
                'exceeds the storage backend limit',
                $e->getMessage(),
            );
        }
    }

    public function test_add_translates_dn_too_long_to_admin_limit_exceeded(): void
    {
        $storage = $this->createPdoStorageWithMaxDnLength(5);
        $backend = $this->backendFor($storage);

        $entry = new Entry(
            new Dn('cn=TooLong,dc=example'),
            new Attribute('cn', 'TooLong'),
        );

        try {
            $backend->add(
                new AddCommand($entry),
                $this->systemContext(),
            );
            self::fail('Expected OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getCode(),
            );
            self::assertInstanceOf(
                DnTooLongException::class,
                $e->getPrevious(),
            );
        }
    }

    public function test_subtree_does_not_match_escaped_comma_suffix_collision(): void
    {
        $storage = $this->pdoStorage(TestServerOptions::sqlite());
        $backend = $this->backendFor($storage);

        $base = new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('dc', 'example'),
        );
        $escaped = new Entry(
            new Dn('cn=Doe\,John,dc=example,dc=com'),
            new Attribute('cn', 'Doe,John'),
        );
        $backend->add(
            new AddCommand($base),
            $this->systemContext(),
        );
        $backend->add(
            new AddCommand($escaped),
            $this->context(),
        );

        $request = (new SearchRequest(new AndFilter()))
            ->base('John,dc=example,dc=com')
            ->useSubtreeScope();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        iterator_to_array($backend->search(
            $request,
            SubentryVisibility::All,
        )->entries);
    }

    public function test_subtree_includes_entries_with_escaped_comma_under_correct_parent(): void
    {
        $storage = $this->pdoStorage(TestServerOptions::sqlite());
        $backend = $this->backendFor($storage);

        $base = new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('dc', 'example'),
        );
        $escaped = new Entry(
            new Dn('cn=Doe\,John,dc=example,dc=com'),
            new Attribute('cn', 'Doe,John'),
        );
        $backend->add(
            new AddCommand($base),
            $this->systemContext(),
        );
        $backend->add(
            new AddCommand($escaped),
            $this->context(),
        );

        $request = (new SearchRequest(new AndFilter()))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        $results = iterator_to_array($backend->search(
            $request,
            SubentryVisibility::All,
        )->entries);

        self::assertCount(2, $results);
    }

    public function test_store_allows_dn_when_dialect_has_no_length_limit(): void
    {
        $longDn = 'cn=' . str_repeat('a', 500) . ',dc=example,dc=com';

        $this->storage->store(new Entry(
            new Dn($longDn),
            new Attribute('cn', str_repeat('a', 500)),
        ));

        self::assertNotNull($this->storage->find(new Dn($longDn)));
    }

    public function test_nested_atomic_rolls_back_inner_on_exception(): void
    {
        $threw = false;

        $this->storage->atomic(function ($storage) use (&$threw): void {
            $storage->store(new Entry(
                new Dn('cn=Outer,dc=example,dc=com'),
                new Attribute('cn', 'Outer'),
            ));

            try {
                $storage->atomic(function ($storage): void {
                    $storage->store(new Entry(
                        new Dn('cn=Inner,dc=example,dc=com'),
                        new Attribute('cn', 'Inner'),
                    ));
                    throw new \RuntimeException('inner fail');
                });
            } catch (\RuntimeException) {
                $threw = true;
            }
        });

        self::assertTrue($threw);
        self::assertNotNull($this->storage->find(new Dn('cn=outer,dc=example,dc=com')));
        self::assertNull($this->storage->find(new Dn('cn=inner,dc=example,dc=com')));
    }

    public function test_naming_contexts_returns_entries_whose_parent_is_missing_in_storage(): void
    {
        $this->storage->store(new Entry(
            new Dn('dc=other,dc=org'),
            new Attribute('dc', 'other'),
        ));

        $contexts = array_map(
            fn(Dn $dn): string => $dn->toString(),
            $this->storage->namingContexts(),
        );

        sort($contexts);
        self::assertSame(
            ['dc=example,dc=com', 'dc=other,dc=org'],
            $contexts,
        );
    }

    public function test_naming_contexts_is_empty_when_storage_is_empty(): void
    {
        $emptyStorage = $this->pdoStorage(TestServerOptions::sqlite());

        self::assertSame(
            [],
            $emptyStorage->namingContexts(),
        );
    }

    public function test_a_journal_append_rolls_back_with_the_enclosing_write_transaction(): void
    {
        $storage = $this->pdoStorage(
            TestServerOptions::sqlite()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
        );

        $journal = $storage->changeJournal() ?? self::fail('Expected the storage to have a journal.');

        try {
            $storage->atomic(function () use ($storage): void {
                $storage->appendChange(new PendingChange(
                    changeType: ChangeType::Add,
                    dn: new Dn('cn=a,dc=example,dc=com'),
                    entryUuid: '11111111-1111-4111-8111-111111111111',
                    authzId: AuthzId::anonymous(),
                ));

                throw new RuntimeException('force rollback');
            });
        } catch (RuntimeException) {
        }

        self::assertCount(
            0,
            iterator_to_array($journal->read()),
        );
        self::assertSame(
            0,
            $journal->latestSeq(),
        );
    }

    /**
     * The subject is the adapter rather than schema enforcement, so its fixtures are not held to one.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::unvalidatedCore();
    }

    protected function makeJournalingStorage(?ChangeJournalInterface $journal = null): ChangeJournalingInterface
    {
        // Built by hand only because the contract injects the journal, which the factory derives from config instead.
        $factory = $this->fromContainer(
            PdoStorageFactory::class,
            options: TestServerOptions::sqlite(),
        );
        $provider = $factory->sharedProvider();
        $statements = new PdoStatementPool($provider);
        $dialect = $this->fromContainer(
            PdoDialectInterface::class,
            options: TestServerOptions::sqlite(),
        );

        return new PdoStorage(
            $provider,
            new SqliteFilterTranslator(
                $this->fromContainer(AttributeContextInterface::class),
                $this->fromContainer(AttributeIndexForms::class),
            ),
            $dialect,
            $this->fromContainer(AttributeContextInterface::class),
            new EntryIndexWriter(
                $dialect,
                $statements,
                $this->fromContainer(AttributeIndexForms::class),
            ),
            $statements,
            journal: $journal,
        );
    }

    /**
     * The container vends the storage interface, while this file asserts on the PDO adapter specifically.
     */
    private function pdoStorage(ServerOptions $options): PdoStorage
    {
        $storage = $this->storageFor($options);

        // Narrowed without asserting, since setUp runs this and some tests expect to perform no assertions.
        return $storage instanceof PdoStorage
            ? $storage
            : self::fail('Expected a PDO configuration to build PDO storage.');
    }

    /**
     * Storage the providers build over a connection the test owns, so it can seed or observe what the driver sees.
     *
     * @param ?PdoDialectInterface $dialect Pass one only to stub what the driver reports, such as its DN limit.
     */
    private function storageOver(
        PDO $pdo,
        ?PdoDialectInterface $dialect = null,
    ): PdoStorage {
        return $this->fromContainer(
            PdoStorageFactory::class,
            $dialect === null ? [] : [PdoDialectInterface::class => $dialect],
            TestServerOptions::sqlite(),
        )->storageOn(new SharedPdoConnectionProvider($pdo));
    }

    /**
     * @param iterable<Entry> $entries
     */
    private function firstByDn(
        iterable $entries,
        string $dn,
    ): ?Entry {
        foreach ($entries as $entry) {
            if ($entry->getDn()->toString() === $dn) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function dnsMatching(FilterInterface $filter): array
    {
        $entries = $this->storage->list(new StorageListOptions(
            baseDn: new Dn('dc=example,dc=com'),
            subtree: true,
            filter: $filter,
        ))->entries;

        $dns = [];
        foreach ($entries as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }

    /**
     * @return list<string>
     */
    private function tableNames(PDO $pdo): array
    {
        $stmt = $pdo->query(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        );

        if ($stmt === false) {
            return [];
        }

        $names = [];
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $name) {
            if (is_string($name)) {
                $names[] = $name;
            }
        }

        return $names;
    }

    /**
     * @return list<string>
     */
    private function searchDns(FilterInterface $filter): array
    {
        $request = (new SearchRequest($filter))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();

        $dns = [];
        foreach ($this->subject->search($request, SubentryVisibility::All)->entries as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }

    private function context(): WriteContext
    {
        return new WriteContext(
            new AnonToken(),
            new ControlBag(),
        );
    }

    private function systemContext(): WriteContext
    {
        return WriteContext::system(
            new AnonToken(),
            new ControlBag(),
        );
    }

    private function createPdoStorageWithMaxDnLength(int $max): PdoStorage
    {
        $pdo = new PDO('sqlite::memory:');

        $sqlite = new SqliteDialect();
        $dialect = $this->createMock(PdoDialectInterface::class);
        $dialect->method('schemaStatements')
            ->willReturn($sqlite->schemaStatements());
        $dialect->method('queryUpsert')
            ->willReturn($sqlite->queryUpsert());
        $dialect->method('queryExists')
            ->willReturn($sqlite->queryExists());
        $dialect->method('queryFetchEntry')
            ->willReturn($sqlite->queryFetchEntry());
        $dialect->method('queryFetchChildren')
            ->willReturn($sqlite->queryFetchChildren());
        $dialect->method('maxDnLength')
            ->willReturn($max);

        PdoStorage::initialize($pdo, $dialect);

        return $this->storageOver(
            $pdo,
            $dialect,
        );
    }
}
