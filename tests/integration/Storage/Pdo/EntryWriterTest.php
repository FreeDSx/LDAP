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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Pdo;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoSchema;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryLister;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryReader;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\EntryWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\Fts5SubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\EntryAlreadyExistsException;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\SubstringIndexMode;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\RecordingPdo;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class EntryWriterTest extends TestCase
{
    private const BASE = 'dc=example,dc=com';

    private const ALICE = 'cn=Alice,dc=example,dc=com';

    private RecordingPdo $pdo;

    private EntryWriter $subject;

    private EntryReader $reader;

    private EntryLister $lister;

    protected function setUp(): void
    {
        $this->pdo = new RecordingPdo('sqlite::memory:');
        (new PdoSchema(new SqliteDialect()))->apply($this->pdo);

        $container = Container::forServer(
            TestServerOptions::sqlite(),
            [PdoConnectionProviderInterface::class => new SharedPdoConnectionProvider($this->pdo)],
        );
        $this->subject = $container->get(EntryWriter::class);
        $this->reader = $container->get(EntryReader::class);
        $this->lister = $container->get(EntryLister::class);
    }

    public function test_store_persists_the_entry(): void
    {
        $this->subject->store(new Entry(
            new Dn('cn=Persistent,dc=example,dc=com'),
            new Attribute('cn', 'Persistent'),
        ));

        self::assertNotNull($this->reader->find(new Dn('cn=persistent,dc=example,dc=com')));
    }

    public function test_insert_persists_the_entry(): void
    {
        $this->subject->insert(new Entry(
            new Dn('cn=Fresh,dc=example,dc=com'),
            new Attribute('cn', 'Fresh'),
        ));

        self::assertNotNull($this->reader->find(new Dn('cn=fresh,dc=example,dc=com')));
    }

    public function test_insert_refuses_a_dn_that_is_taken(): void
    {
        $this->storeNamed('Alice');

        $this->expectException(EntryAlreadyExistsException::class);

        $this->subject->insert(new Entry(
            new Dn(self::ALICE),
            new Attribute('cn', 'Alice'),
        ));
    }

    public function test_insert_leaves_the_entry_it_refused_untouched(): void
    {
        $this->storeNamed('Alice');

        try {
            $this->subject->insert(new Entry(
                new Dn(self::ALICE),
                new Attribute('cn', 'Alice'),
                new Attribute('description', 'overwritten'),
            ));
        } catch (EntryAlreadyExistsException) {
            // Expected, since the DN is taken.
        }

        self::assertNull($this->reader->find(new Dn(self::ALICE))?->get('description'));
    }

    public function test_renaming_a_subtree_onto_an_occupied_dn_is_refused(): void
    {
        $this->storeNamed('Alice');
        $this->storeNamed('Taken');

        $this->expectException(EntryAlreadyExistsException::class);

        $this->subject->renameSubtree(
            new Dn(self::ALICE),
            new Dn('cn=Taken,dc=example,dc=com'),
        );
    }

    public function test_remove_deletes_the_entry(): void
    {
        $this->storeNamed('Alice');

        $this->subject->remove(new Dn(self::ALICE));

        self::assertNull($this->reader->find(new Dn(self::ALICE)));
    }

    public function test_remove_all_deletes_every_given_entry_and_ignores_missing_ones(): void
    {
        foreach (range(1, 3) as $i) {
            $this->storeNamed("e{$i}");
        }

        $this->subject->removeAll([
            (new Dn('cn=e1,dc=example,dc=com'))->normalize(),
            (new Dn('cn=gone,dc=example,dc=com'))->normalize(),
            (new Dn('cn=e3,dc=example,dc=com'))->normalize(),
        ]);

        self::assertFalse($this->reader->exists(new Dn('cn=e1,dc=example,dc=com')));
        self::assertTrue($this->reader->exists(new Dn('cn=e2,dc=example,dc=com')));
        self::assertFalse($this->reader->exists(new Dn('cn=e3,dc=example,dc=com')));
    }

    public function test_remove_all_spans_more_entries_than_one_batch(): void
    {
        $dns = [];
        foreach (range(1, 1200) as $i) {
            $dns[] = $this->storeNamed("b{$i}");
        }

        $this->subject->removeAll($dns);

        self::assertFalse($this->reader->exists(new Dn('cn=b1,dc=example,dc=com')));
        self::assertFalse($this->reader->exists(new Dn('cn=b600,dc=example,dc=com')));
        self::assertFalse($this->reader->exists(new Dn('cn=b1200,dc=example,dc=com')));
    }

    public function test_a_dn_longer_than_the_dialect_allows_is_refused(): void
    {
        $dialect = $this->createStub(PdoDialectInterface::class);
        $dialect->method('maxDnLength')
            ->willReturn(10);
        $subject = Container::forServer(
            TestServerOptions::sqlite(),
            [
                PdoConnectionProviderInterface::class => new SharedPdoConnectionProvider($this->pdo),
                PdoDialectInterface::class => $dialect,
            ],
        )->get(EntryWriter::class);

        $this->expectException(DnTooLongException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);
        $this->expectExceptionMessage('exceeds the storage backend limit');

        $subject->store(new Entry(
            new Dn('cn=VeryLongNameThatExceedsTheLimit,dc=example,dc=com'),
            new Attribute('cn', 'VeryLongNameThatExceedsTheLimit'),
        ));
    }

    public function test_a_long_dn_is_stored_when_the_dialect_has_no_length_limit(): void
    {
        $longDn = 'cn=' . str_repeat('a', 500) . ',dc=example,dc=com';

        $this->subject->store(new Entry(
            new Dn($longDn),
            new Attribute('cn', str_repeat('a', 500)),
        ));

        self::assertNotNull($this->reader->find(new Dn($longDn)));
    }

    public function test_an_attribute_wider_than_one_statement_writes_every_index_row(): void
    {
        $this->subject->store(new Entry(
            new Dn('cn=wide,dc=example,dc=com'),
            new Attribute('cn', 'wide'),
            new Attribute('description', ...$this->values('wide value', 1000)),
        ));

        self::assertSame(
            200,
            $this->widestSidecarInsert(),
        );
        self::assertSame(
            ['cn=wide,dc=example,dc=com'],
            $this->dnsMatching(Filters::equal('description', 'wide value 999')),
        );
    }

    public function test_adding_one_value_writes_one_index_row_rather_than_the_whole_attribute(): void
    {
        $values = $this->values('growing value', 300);
        $this->storeDescribed('growing', ...$values);
        $this->pdo->prepared = [];

        $this->storeDescribed('growing', ...[...$values, 'growing value 301']);

        self::assertSame(
            1,
            $this->widestSidecarInsert(),
        );
        self::assertSame(
            [],
            $this->pdo->preparedMatching('DELETE FROM entry_attribute_values'),
        );
    }

    public function test_removing_one_value_deletes_one_index_row_and_inserts_nothing(): void
    {
        $values = $this->values('shrinking value', 300);
        $this->storeDescribed('shrinking', ...$values);
        $this->pdo->prepared = [];

        array_pop($values);
        $this->storeDescribed('shrinking', ...$values);

        self::assertCount(
            1,
            $this->pdo->preparedMatching('(attr_name_lower, value_lower) IN'),
        );
        self::assertSame(
            [],
            $this->pdo->preparedMatching('INSERT INTO entry_attribute_values'),
        );
    }

    public function test_a_modify_of_another_attribute_leaves_a_wide_attributes_index_untouched(): void
    {
        $dn = new Dn('cn=stable,dc=example,dc=com');
        $values = $this->values('stable value', 300);
        $this->subject->store(new Entry(
            $dn,
            new Attribute('cn', 'stable'),
            new Attribute('title', 'before'),
            new Attribute('description', ...$values),
        ));
        $this->pdo->prepared = [];

        $this->subject->store(new Entry(
            $dn,
            new Attribute('cn', 'stable'),
            new Attribute('title', 'after'),
            new Attribute('description', ...$values),
        ));

        self::assertSame(
            1,
            $this->widestSidecarInsert(),
        );
        self::assertSame(
            ['cn=stable,dc=example,dc=com'],
            $this->dnsMatching(Filters::equal('description', 'stable value 300')),
        );
    }

    public function test_a_swapped_value_leaves_the_index_matching_the_survivors_and_the_new_value(): void
    {
        $this->storeDescribed('swapped', 'kept value', 'old value');

        $this->storeDescribed('swapped', 'kept value', 'new value');

        self::assertSame(
            ['cn=swapped,dc=example,dc=com'],
            $this->dnsMatching(Filters::equal('description', 'kept value')),
        );
        self::assertSame(
            ['cn=swapped,dc=example,dc=com'],
            $this->dnsMatching(Filters::equal('description', 'new value')),
        );
        self::assertSame(
            [],
            $this->dnsMatching(Filters::equal('description', 'old value')),
        );
    }

    public function test_a_modified_value_stops_matching_its_old_value_and_starts_matching_the_new(): void
    {
        $dn = new Dn('cn=drift,dc=example,dc=com');
        $this->subject->store(new Entry(
            $dn,
            new Attribute('cn', 'drift'),
            new Attribute('sn', 'before'),
            new Attribute('description', 'untouched'),
        ));

        $this->subject->store(new Entry(
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
        $this->subject->store(new Entry(
            $dn,
            new Attribute('cn', 'shrink'),
            new Attribute('sn', 'gone'),
        ));

        $this->subject->store(new Entry(
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

    public function test_an_update_reindexes_a_base_form_an_option_bearing_form_shares_a_name_with(): void
    {
        $dn = new Dn('cn=subtyped,dc=example,dc=com');
        $this->subject->store(new Entry(
            $dn,
            new Attribute('cn', 'subtyped'),
            new Attribute('mail', 'base@example.com'),
            new Attribute('mail;lang-en', 'tagged@example.com'),
        ));

        $this->subject->store(new Entry(
            $dn,
            new Attribute('cn', 'subtyped'),
            new Attribute('mail', 'replaced@example.com'),
            new Attribute('mail;lang-en', 'tagged@example.com'),
        ));

        self::assertSame(
            ['cn=subtyped,dc=example,dc=com'],
            $this->dnsMatching(Filters::equal('mail', 'replaced@example.com')),
        );
        self::assertSame(
            [],
            $this->dnsMatching(Filters::equal('mail', 'base@example.com')),
        );
        self::assertSame(
            ['cn=subtyped,dc=example,dc=com'],
            $this->dnsMatching(Filters::equal('mail', 'tagged@example.com')),
        );
    }

    public function test_store_writes_trigram_rows_for_indexed_attributes(): void
    {
        [$subject, $pdo] = $this->indexedWith(SubstringIndexMode::Trigram);

        $subject->store(new Entry(
            new Dn('cn=Smith,dc=example,dc=com'),
            new Attribute('cn', 'Smith'),
        ));

        self::assertSame(
            1,
            $this->intQuery(
                $pdo,
                "SELECT COUNT(*) FROM entry_attribute_trigrams WHERE trigram = 'smi'",
            ),
        );
    }

    public function test_store_keeps_the_original_value_only_where_the_index_reads_it(): void
    {
        if (!Fts5SubstringIndex::isSupported()) {
            self::markTestSkipped('This SQLite build lacks the FTS5 trigram tokenizer.');
        }

        self::assertSame(
            [
                'cn' => 'Smith',
                'description' => '',
            ],
            $this->originalValuesFor(SubstringIndexMode::Auto),
        );
    }

    public function test_store_omits_every_original_value_when_no_index_reads_them(): void
    {
        self::assertSame(
            [
                'cn' => '',
                'description' => '',
            ],
            $this->originalValuesFor(SubstringIndexMode::Trigram),
        );
    }

    private function storeNamed(string $cn): Dn
    {
        $dn = new Dn("cn={$cn},dc=example,dc=com");
        $this->subject->store(new Entry(
            $dn,
            new Attribute('cn', $cn),
        ));

        return $dn->normalize();
    }

    private function storeDescribed(
        string $cn,
        string ...$descriptions,
    ): void {
        $this->subject->store(new Entry(
            new Dn("cn={$cn},dc=example,dc=com"),
            new Attribute('cn', $cn),
            new Attribute('description', ...$descriptions),
        ));
    }

    /**
     * @return list<string>
     */
    private function values(
        string $prefix,
        int $count,
    ): array {
        return array_map(
            static fn(int $i): string => "{$prefix} {$i}",
            range(1, $count),
        );
    }

    /**
     * @return list<string>
     */
    private function dnsMatching(FilterInterface $filter): array
    {
        $dns = [];
        foreach ($this->lister->list(new StorageListOptions(new Dn(self::BASE), true, $filter))->entries() as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }

    /**
     * Tuples in the largest sidecar insert prepared so far, or zero when none was, which bounds the placeholder count.
     */
    private function widestSidecarInsert(): int
    {
        $widest = 0;

        foreach ($this->pdo->preparedMatching('INSERT INTO entry_attribute_values') as $sql) {
            $widest = max(
                $widest,
                substr_count($sql, '(?, ?, ?, ?)'),
            );
        }

        return $widest;
    }

    /**
     * A writer and its connection over a fresh database set up for the given substring index mode.
     *
     * @return array{EntryWriter, PDO}
     */
    private function indexedWith(SubstringIndexMode $mode): array
    {
        $container = Container::forServer(TestServerOptions::forStorage(
            PdoConfig::forSqlite(':memory:')
                ->setSubstringIndexMode($mode),
        ));

        return [
            $container->get(EntryWriter::class),
            $container->get(PdoConnection::class)->pdo(),
        ];
    }

    /**
     * The sidecar's value_original per attribute, for an entry holding one indexed and one unindexed attribute.
     *
     * @return array<string, string>
     */
    private function originalValuesFor(SubstringIndexMode $mode): array
    {
        [$subject, $pdo] = $this->indexedWith($mode);
        $subject->store(new Entry(
            new Dn('cn=Smith,dc=example,dc=com'),
            new Attribute('cn', 'Smith'),
            new Attribute('description', 'Not an indexed attribute'),
        ));

        $rows = $pdo->query(
            "SELECT attr_name_lower, value_original FROM entry_attribute_values
             WHERE attr_name_lower IN ('cn', 'description')",
        );
        self::assertNotFalse($rows);

        $found = [];
        foreach ($rows->fetchAll(PDO::FETCH_NUM) as $row) {
            self::assertIsArray($row);
            self::assertIsString($row[0]);
            self::assertIsString($row[1]);
            $found[$row[0]] = $row[1];
        }
        ksort($found);

        return $found;
    }

    private function intQuery(
        PDO $pdo,
        string $sql,
    ): int {
        $statement = $pdo->query($sql);
        self::assertNotFalse($statement);

        $value = $statement->fetchColumn();
        self::assertIsNumeric($value);

        return (int) $value;
    }
}
