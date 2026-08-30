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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Journal\JournalingStorageContractTests;
use Tests\Support\FreeDSx\Ldap\Storage\SubtreeRenameStorageContractTests;

final class InMemoryStorageTest extends TestCase
{
    use JournalingStorageContractTests;

    use SubtreeRenameStorageContractTests;

    private InMemoryStorage $subject;

    private Entry $alice;

    protected function setUp(): void
    {
        $this->alice = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
        );
        $this->subject = new InMemoryStorage([$this->alice]);
    }

    public function test_find_returns_entry_by_norm_dn(): void
    {
        $entry = $this->subject->find(new Dn('cn=alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $entry->getDn()->toString(),
        );
    }

    public function test_atomic_discards_entries_stored_before_a_failure(): void
    {
        $bob = new Entry(
            new Dn('cn=Bob,dc=example,dc=com'),
            new Attribute('cn', 'Bob'),
        );

        try {
            $this->subject->atomic(function () use ($bob): void {
                $this->subject->store($bob);

                throw new RuntimeException('failed part way through');
            });
            self::fail('The failure should have propagated.');
        } catch (RuntimeException) {
        }

        self::assertNull(
            $this->subject->find(new Dn('cn=Bob,dc=example,dc=com')),
            'A seed failing on entry N must not leave the ones before it behind.',
        );
    }

    public function test_atomic_discards_a_modification_made_in_place(): void
    {
        try {
            $this->subject->atomic(function (): void {
                $this->subject->find(new Dn('cn=Alice,dc=example,dc=com'))
                    ?->set(new Attribute('cn', 'Changed'));

                throw new RuntimeException('failed part way through');
            });
            self::fail('The failure should have propagated.');
        } catch (RuntimeException) {
        }

        self::assertSame(
            ['Alice'],
            $this->subject->find(new Dn('cn=Alice,dc=example,dc=com'))?->get('cn')?->getValues(),
        );
    }

    public function test_atomic_keeps_its_changes_when_the_operation_succeeds(): void
    {
        $bob = new Entry(
            new Dn('cn=Bob,dc=example,dc=com'),
            new Attribute('cn', 'Bob'),
        );

        $this->subject->atomic(function () use ($bob): void {
            $this->subject->store($bob);
        });

        self::assertNotNull($this->subject->find(new Dn('cn=Bob,dc=example,dc=com')));
    }

    public function test_find_returns_null_for_unknown_norm_dn(): void
    {
        self::assertNull($this->subject->find(new Dn('cn=nobody,dc=example,dc=com')));
    }

    public function test_find_matches_whitespace_and_case_variant_dn(): void
    {
        $entry = $this->subject->find(new Dn('CN = Alice , dc=example , dc=com'));

        self::assertNotNull($entry);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $entry->getDn()->toString(),
        );
    }

    public function test_list_returns_all_entries(): void
    {
        $entries = iterator_to_array($this->subject->list(StorageListOptions::matchAll(new Dn(''), true))->entries);

        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $entries[0]->getDn()->toString(),
        );
    }

    public function test_list_single_level_returns_direct_children_only(): void
    {
        $parent = new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'));
        $child = new Entry(new Dn('cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Bob'));
        $grandchild = new Entry(new Dn('cn=Sub,cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $storage = new InMemoryStorage([$parent, $child, $grandchild]);

        $entries = iterator_to_array($storage->list(StorageListOptions::matchAll(new Dn('dc=example,dc=com'), false))->entries);

        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            'cn=Bob,dc=example,dc=com',
            $entries[0]->getDn()->toString(),
        );
    }

    public function test_list_recursive_includes_base_and_descendants(): void
    {
        $parent = new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'));
        $child = new Entry(new Dn('cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Bob'));
        $grandchild = new Entry(new Dn('cn=Sub,cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $storage = new InMemoryStorage([$parent, $child, $grandchild]);

        $entries = iterator_to_array(
            $storage->list(StorageListOptions::matchAll(
                new Dn('dc=example,dc=com'),
                true,
            ))->entries,
        );

        $dns = array_map(
            static fn(Entry $entry): string => $entry->getDn()->toString(),
            $entries,
        );

        self::assertContains(
            'dc=example,dc=com',
            $dns,
        );
        self::assertContains(
            'cn=Bob,dc=example,dc=com',
            $dns,
        );
        self::assertContains(
            'cn=Sub,cn=Bob,dc=example,dc=com',
            $dns,
        );
        self::assertCount(
            3,
            $entries,
        );
    }

    public function test_list_subtree_does_not_match_string_suffix_collision(): void
    {
        // The escaped comma in the RDN value would let a naive str_ends_with
        // match consider this entry a descendant of "John,dc=example,dc=com",
        // even though its actual parent is "dc=example,dc=com".
        $entry = new Entry(
            new Dn('cn=Doe\,John,dc=example,dc=com'),
            new Attribute('cn', 'Doe,John'),
        );
        $storage = new InMemoryStorage([$entry]);

        $entries = iterator_to_array($storage->list(StorageListOptions::matchAll(
            new Dn('John,dc=example,dc=com'),
            true,
        ))->entries);

        self::assertCount(
            0,
            $entries,
        );
    }

    public function test_has_children_returns_true_when_children_exist(): void
    {
        $parent = new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'));
        $child = new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alice'));
        $storage = new InMemoryStorage([$parent, $child]);

        self::assertTrue($storage->hasChildren(new Dn('dc=example,dc=com')));
    }

    public function test_has_children_returns_false_for_leaf_entry(): void
    {
        self::assertFalse($this->subject->hasChildren(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_store_adds_entry(): void
    {
        $bob = new Entry(new Dn('cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Bob'));
        $this->subject->store($bob);

        self::assertNotNull($this->subject->find(new Dn('cn=bob,dc=example,dc=com')));
    }

    public function test_store_replaces_existing_entry(): void
    {
        $updated = new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alicia'));
        $this->subject->store($updated);

        $entry = $this->subject->find(new Dn('cn=alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertSame(
            ['Alicia'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_remove_deletes_entry(): void
    {
        $this->subject->remove(new Dn('cn=alice,dc=example,dc=com'));

        self::assertNull($this->subject->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_remove_is_noop_for_unknown_norm_dn(): void
    {
        $this->subject->remove(new Dn('cn=nobody,dc=example,dc=com'));

        self::assertCount(
            1,
            iterator_to_array(
                $this->subject->list(
                    StorageListOptions::matchAll(
                        new Dn(''),
                        true,
                    ),
                )->entries,
            ),
        );
    }

    public function test_constructor_normalises_dn_keys(): void
    {
        $entry = new Entry(new Dn('CN=ALICE,DC=EXAMPLE,DC=COM'), new Attribute('cn', 'Alice'));
        $storage = new InMemoryStorage([$entry]);

        self::assertNotNull($storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_empty_constructor_creates_empty_storage(): void
    {
        $storage = new InMemoryStorage();

        self::assertCount(
            0,
            iterator_to_array($storage->list(StorageListOptions::matchAll(new Dn(''), true))->entries),
        );
    }

    public function test_list_with_zero_time_limit_returns_all_entries(): void
    {
        $parent = new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'));
        $child = new Entry(new Dn('cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Bob'));
        $storage = new InMemoryStorage([$parent, $child]);

        $entries = iterator_to_array(
            $storage->list(StorageListOptions::matchAll(
                new Dn('dc=example,dc=com'),
                true,
            ))->entries,
        );

        self::assertCount(2, $entries);
    }

    public function test_list_with_positive_time_limit_returns_entries_when_within_deadline(): void
    {
        $parent = new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'));
        $child = new Entry(new Dn('cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Bob'));
        $storage = new InMemoryStorage([$parent, $child]);

        $entries = iterator_to_array(
            $storage->list(StorageListOptions::matchAll(
                new Dn('dc=example,dc=com'),
                true,
                timeLimit: 60,
            ))->entries,
        );

        self::assertCount(2, $entries);
    }

    public function test_naming_contexts_is_empty_when_storage_is_empty(): void
    {
        self::assertSame(
            [],
            (new InMemoryStorage())->namingContexts(),
        );
    }

    public function test_naming_contexts_returns_entries_whose_parent_is_missing(): void
    {
        $storage = new InMemoryStorage([
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alice')),
            new Entry(new Dn('dc=other,dc=org'), new Attribute('dc', 'other')),
        ]);

        $contexts = array_map(
            fn(Dn $dn): string => $dn->toString(),
            $storage->namingContexts(),
        );

        sort($contexts);
        self::assertSame(
            ['dc=example,dc=com', 'dc=other,dc=org'],
            $contexts,
        );
    }

    public function test_naming_contexts_returns_orphans_whose_parent_is_not_in_storage(): void
    {
        $storage = new InMemoryStorage([
            new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alice')),
        ]);

        $contexts = array_map(
            fn(Dn $dn): string => $dn->toString(),
            $storage->namingContexts(),
        );

        self::assertSame(
            ['cn=alice,dc=example,dc=com'],
            $contexts,
        );
    }

    public function test_the_injected_journal_keeps_the_origin_it_was_built_with(): void
    {
        $storage = new InMemoryStorage(
            [],
            new InMemoryChangeJournal(new ReplicaId('node-x')),
        );

        self::assertTrue($storage->changeJournal()?->origin()->equals(new ReplicaId('node-x')));
    }

    protected function makeJournalingStorage(?ChangeJournalInterface $journal = null): ChangeJournalingInterface
    {
        return new InMemoryStorage(
            [],
            $journal,
        );
    }

    protected function makeRenameStorage(Entry ...$entries): EntryStorageInterface
    {
        return new InMemoryStorage($entries);
    }
}
