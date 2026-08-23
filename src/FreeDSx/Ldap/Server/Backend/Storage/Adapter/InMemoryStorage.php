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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\ArrayEntryStorageTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\SortKeyComparator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\SubtreeRename;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Array-backed storage; safe under Swoole or as a pre-seeded read-only fixture under PCNTL (child writes are not shared).
 *
 * @internal built from InMemoryStorageConfig via ServerOptions::setStorageConfig()
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class InMemoryStorage implements EntryStorageInterface, ChangeJournalingInterface
{
    use ArrayEntryStorageTrait;
    use ChangeJournalingTrait;

    /**
     * @var array<string, Entry> keyed by normalised DN string
     */
    private array $entries = [];

    /**
     * Assigned rather than derived from the DN, so a resumed walk is not disturbed by a rename.
     *
     * @var array<string, int> entry key, keyed by normalised DN string
     */
    private array $keys = [];

    private int $nextKey = 1;

    /**
     * @param Entry[] $entries pre-populated into the store
     */
    public function __construct(
        array $entries = [],
        ?ChangeJournalInterface $journal = null,
        SortKeyComparator $sortKeyComparator = new SortKeyComparator(),
    ) {
        $this->sortKeyComparator = $sortKeyComparator;
        $this->journal = $journal;

        foreach ($entries as $entry) {
            $this->store($entry);
        }
    }

    public function find(Dn $dn): ?Entry
    {
        return $this->entries[$dn->normalize()->toString()] ?? null;
    }

    public function exists(Dn $dn): bool
    {
        return isset($this->entries[$dn->normalize()->toString()]);
    }

    public function list(StorageListOptions $options): EntryStream
    {
        return $this->listFromArray(
            $options,
            $this->entries,
            $this->keys,
        );
    }

    public function store(
        Entry $entry,
        bool $rebuildIndexes = false,
    ): void {
        $lcDn = $entry->getDn()->normalize()->toString();

        // Overwriting an entry keeps its key, matching the upsert the database adapters do.
        $this->keys[$lcDn] ??= $this->nextKey++;
        $this->entries[$lcDn] = $entry;
    }

    public function renameSubtree(
        Dn $from,
        Dn $to,
    ): void {
        $base = $this->find($from);
        if ($base === null) {
            return;
        }

        $rename = new SubtreeRename(
            $from,
            $to,
            $base->getDn()->toString(),
        );

        $this->entries = $rename->applyTo(
            $this->entries,
            static fn(Entry $entry): Entry => Entry::raw(
                $rename->storedFor($entry->getDn()),
                $entry->getAttributes(),
            ),
        );

        // Re-keyed the same way and in the same order, so a walk in progress keeps both its position and its ordering.
        $this->keys = $rename->applyTo(
            $this->keys,
            static fn(int $key): int => $key,
        );
    }

    public function remove(Dn $dn): void
    {
        $lcDn = $dn->normalize()->toString();

        unset($this->entries[$lcDn], $this->keys[$lcDn]);
    }

    public function removeAll(array $dns): void
    {
        foreach ($dns as $dn) {
            $this->remove($dn);
        }
    }

    public function atomic(callable $operation): void
    {
        $operation($this);
    }

    public function namingContexts(): array
    {
        return $this->namingContextsFromArray($this->entries);
    }
}
