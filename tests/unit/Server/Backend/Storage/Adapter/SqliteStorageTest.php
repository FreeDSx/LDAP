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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqliteStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use PDO;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class SqliteStorageTest extends TestCase
{
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

        $this->storage = SqliteStorage::forPcntl(':memory:');
        $this->subject = new WritableStorageBackend($this->storage);
        $this->subject->add(new AddCommand(
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
        ));
        $this->subject->add(new AddCommand($this->alice));
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
        $storage = SqliteStorage::forPcntl(':memory:');
        $backend = new WritableStorageBackend($storage);

        self::assertNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_add_persists_entry(): void
    {
        $entry = new Entry(new Dn('cn=Persistent,dc=example,dc=com'), new Attribute('cn', 'Persistent'));
        $this->subject->add(new AddCommand($entry));

        self::assertNotNull($this->subject->get(new Dn('cn=Persistent,dc=example,dc=com')));
    }

    public function test_delete_removes_entry(): void
    {
        $this->subject->delete(new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')));

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_list_single_level_returns_direct_children_only(): void
    {
        $grandchild = new Entry(new Dn('cn=Sub,cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $this->subject->add(new AddCommand($grandchild));

        $request = (new SearchRequest(new AndFilter()))
            ->base('dc=example,dc=com')
            ->useSingleLevelScope();
        $results = iterator_to_array($this->subject->search($request)->entries);

        self::assertCount(1, $results);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $results[0]->getDn()->toString(),
        );
    }

    public function test_list_recursive_includes_base_and_descendants(): void
    {
        $grandchild = new Entry(new Dn('cn=Sub,cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $this->subject->add(new AddCommand($grandchild));

        $request = (new SearchRequest(new AndFilter()))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        $results = iterator_to_array($this->subject->search($request)->entries);

        self::assertCount(3, $results);
    }

    public function test_list_from_root_returns_all_entries(): void
    {
        // Test the storage interface directly with an empty base DN (root listing).
        // WritableStorageBackend requires the base DN to exist, so bypass it here.
        $results = iterator_to_array($this->storage->list(StorageListOptions::matchAll(new Dn(''), true))->entries);

        self::assertCount(2, $results);
    }

    public function test_interleaved_lists_do_not_share_cursor_state(): void
    {
        $this->subject->add(new AddCommand(
            new Entry(new Dn('cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Bob')),
        ));
        $this->subject->add(new AddCommand(
            new Entry(new Dn('cn=Carol,dc=example,dc=com'), new Attribute('cn', 'Carol')),
        ));

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

        $results = iterator_to_array($this->subject->search($request)->entries);

        self::assertCount(1, $results);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $results[0]->getDn()->toString(),
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

        $storage = new PdoStorage(
            new SharedPdoConnectionProvider($mockPdo),
            $this->createMock(FilterTranslatorInterface::class),
            new SqliteDialect(),
        );

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

        $storage = new PdoStorage(
            new SharedPdoConnectionProvider($mockPdo),
            $this->createMock(FilterTranslatorInterface::class),
            new SqliteDialect(),
        );

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

        $storage = new PdoStorage(
            new SharedPdoConnectionProvider($mockPdo),
            $this->createMock(FilterTranslatorInterface::class),
            new SqliteDialect(),
        );

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

        $storage = new PdoStorage(
            new SharedPdoConnectionProvider($mockPdo),
            $this->createMock(FilterTranslatorInterface::class),
            new SqliteDialect(),
        );

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

        $storage = new PdoStorage(
            new SharedPdoConnectionProvider($mockPdo),
            $this->createMock(FilterTranslatorInterface::class),
            new SqliteDialect(),
        );

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
            "INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes) VALUES " .
            "('cn=corrupt,dc=example,dc=com', 'cn=Corrupt,dc=example,dc=com', 'dc=example,dc=com', 'NOT_VALID_BLOB')"
        );

        $storage = new PdoStorage(
            new SharedPdoConnectionProvider($pdo),
            $this->createMock(FilterTranslatorInterface::class),
            $dialect,
        );

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
            "INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes) VALUES " .
            "('cn=valid,dc=example,dc=com', 'cn=Valid,dc=example,dc=com', 'dc=example,dc=com', '{$validBlob}')"
        );
        $pdo->exec(
            "INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes) VALUES " .
            "('cn=corrupt,dc=example,dc=com', 'cn=Corrupt,dc=example,dc=com', 'dc=example,dc=com', 'NOT_VALID_BLOB')"
        );

        $storage = new PdoStorage(
            new SharedPdoConnectionProvider($pdo),
            $this->createMock(FilterTranslatorInterface::class),
            $dialect,
        );

        $this->expectException(StorageIoException::class);

        iterator_to_array(
            $storage->list(StorageListOptions::matchAll(new Dn('dc=example,dc=com'), false))->entries
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
        $backend = new WritableStorageBackend($storage);

        // Use a root-level parent (dc=example) so assertParentExists skips the lookup
        // and the path reaches PdoStorage::store() where the DnTooLongException fires.
        $entry = new Entry(
            new Dn('cn=TooLong,dc=example'),
            new Attribute('cn', 'TooLong'),
        );

        try {
            $backend->add(new AddCommand($entry));
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
        $storage = SqliteStorage::forPcntl(':memory:');
        $backend = new WritableStorageBackend($storage);

        $base = new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('dc', 'example'),
        );
        $escaped = new Entry(
            new Dn('cn=Doe\,John,dc=example,dc=com'),
            new Attribute('cn', 'Doe,John'),
        );
        $backend->add(new AddCommand($base));
        $backend->add(new AddCommand($escaped));

        $request = (new SearchRequest(new AndFilter()))
            ->base('John,dc=example,dc=com')
            ->useSubtreeScope();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        iterator_to_array($backend->search($request)->entries);
    }

    public function test_subtree_includes_entries_with_escaped_comma_under_correct_parent(): void
    {
        $storage = SqliteStorage::forPcntl(':memory:');
        $backend = new WritableStorageBackend($storage);

        $base = new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('dc', 'example'),
        );
        $escaped = new Entry(
            new Dn('cn=Doe\,John,dc=example,dc=com'),
            new Attribute('cn', 'Doe,John'),
        );
        $backend->add(new AddCommand($base));
        $backend->add(new AddCommand($escaped));

        $request = (new SearchRequest(new AndFilter()))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        $results = iterator_to_array($backend->search($request)->entries);

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

    private function createPdoStorageWithMaxDnLength(int $max): PdoStorage
    {
        $pdo = new PDO('sqlite::memory:');

        $sqlite = new SqliteDialect();
        $dialect = $this->createMock(PdoDialectInterface::class);
        $dialect->method('ddlCreateTable')
            ->willReturn($sqlite->ddlCreateTable());
        $dialect->method('ddlCreateIndex')
            ->willReturn($sqlite->ddlCreateIndex());
        $dialect->method('ddlCreateSidecarTable')
            ->willReturn($sqlite->ddlCreateSidecarTable());
        $dialect->method('ddlCreateSidecarIndexes')
            ->willReturn($sqlite->ddlCreateSidecarIndexes());
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

        return new PdoStorage(
            new SharedPdoConnectionProvider($pdo),
            $this->createMock(FilterTranslatorInterface::class),
            $dialect,
        );
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
}
