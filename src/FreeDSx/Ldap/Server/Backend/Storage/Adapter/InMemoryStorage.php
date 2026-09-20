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
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\EntryAlreadyExistsException;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use Throwable;

/**
 * Array-backed storage; safe under Swoole or as a pre-seeded read-only fixture under PCNTL (child writes are not shared).
 *
 * @internal built from InMemoryStorageConfig via ServerOptions::setStorageConfig()
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class InMemoryStorage implements
    ReadEntryInterface,
    ListEntryInterface,
    WriteEntryInterface,
    TransactionalWriteInterface,
    LinkedValueLookupInterface
{
    use ArrayEntryStorageTrait;

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

    private int $atomicDepth = 0;

    /**
     * @param Entry[] $entries pre-populated into the store
     */
    public function __construct(
        array $entries = [],
        SortKeyComparator $sortKeyComparator = new SortKeyComparator(),
    ) {
        $this->sortKeyComparator = $sortKeyComparator;

        foreach ($entries as $entry) {
            $this->store($entry);
        }
    }

    public function find(
        Dn $dn,
        EntryProjection $projection = new EntryProjection(),
    ): ?Entry {
        $entry = $this->entries[$dn->normalizedString()] ?? null;

        return $entry === null || $projection->windows === []
            ? $entry
            : $this->sliced($entry, $projection);
    }

    public function exists(Dn $dn): bool
    {
        return isset($this->entries[$dn->normalizedString()]);
    }

    public function list(StorageListOptions $options): EntryStream
    {
        return $this->listFromArray(
            $options,
            $this->entries,
            $this->keys,
        );
    }

    public function insert(Entry $entry): void
    {
        $lcDn = $entry->getDn()->normalizedString();

        if (isset($this->entries[$lcDn])) {
            throw new EntryAlreadyExistsException(
                sprintf('Entry already exists: %s', $lcDn),
            );
        }

        $this->store($entry);
    }

    public function store(
        Entry $entry,
        bool $rebuildIndexes = false,
        LinkDelta $links = new LinkDelta(),
    ): void {
        $lcDn = $entry->getDn()->normalizedString();

        // Overwriting an entry keeps its key, matching the upsert the database adapters do.
        $this->keys[$lcDn] ??= $this->nextKey++;
        $this->entries[$lcDn] = $this->withLinks(
            $entry,
            $links,
            $this->entries[$lcDn] ?? null,
        );
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
        $lcDn = $dn->normalizedString();

        unset($this->entries[$lcDn], $this->keys[$lcDn]);
    }

    public function removeAll(array $dns): void
    {
        foreach ($dns as $dn) {
            $this->remove($dn);
        }
    }

    /**
     * Makes and restores copies for failures since in-memory mutates in place.
     */
    public function atomic(callable $operation): mixed
    {
        // Only the outermost call snapshots...
        if ($this->atomicDepth > 0) {
            $this->atomicDepth++;

            try {
                return $operation();
            } finally {
                $this->atomicDepth--;
            }
        }

        $entries = array_map(
            static fn(Entry $entry): Entry => $entry->makeCopy(),
            $this->entries,
        );
        $keys = $this->keys;
        $nextKey = $this->nextKey;
        $this->atomicDepth = 1;

        try {
            return $operation();
        } catch (Throwable $e) {
            $this->entries = $entries;
            $this->keys = $keys;
            $this->nextKey = $nextKey;

            throw $e;
        } finally {
            $this->atomicDepth = 0;
        }
    }

    public function namingContexts(): array
    {
        return $this->namingContextsFromArray($this->entries);
    }

    /**
     * Which of the named values the entry holds, matched as DNs since that is what a linked value is.
     */
    public function heldLinkValues(
        Dn $owner,
        string $attribute,
        array $values,
    ): array {
        $held = $this->linkedValuesOf($owner, $attribute);

        if ($held === []) {
            return [];
        }

        return array_values(array_filter(
            $values,
            static fn(string $value): bool => in_array(
                Dn::normalizedOrNull($value),
                $held,
                true,
            ),
        ));
    }

    public function anyLinkValue(
        Dn $owner,
        string $attribute,
    ): ?string {
        return $this->find($owner)
            ?->get($attribute, true)
            ?->getValues()[0] ?? null;
    }

    /**
     * @return list<string> the normalised form of every value the entry holds for the attribute
     */
    private function linkedValuesOf(
        Dn $owner,
        string $attribute,
    ): array {
        $values = $this->find($owner)
            ?->get($attribute, true)
            ?->getValues() ?? [];

        return array_values(array_filter(array_map(
            static fn(string $value): ?string => Dn::normalizedOrNull($value),
            $values,
        )));
    }

    /**
     * A delta names only what changes, and the entry carrying it no longer holds the attribute it changes.
     */
    private function withLinks(
        Entry $entry,
        LinkDelta $links,
        ?Entry $previous,
    ): Entry {
        if ($links->isEmpty()) {
            return $entry;
        }
        $updated = $entry->makeCopy();

        foreach ($links->names() as $name) {
            $values = array_merge(
                array_diff(
                    $previous?->get($name, true)?->getValues() ?? [],
                    $links->removed($name),
                ),
                $links->added($name),
            );

            $values === []
                ? $updated->reset($name)
                : $updated->set($name, ...$values);
        }

        return $updated;
    }
}
