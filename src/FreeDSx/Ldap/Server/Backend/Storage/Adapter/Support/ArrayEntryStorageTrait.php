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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Search\Filter\FilterAttributes;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedBatch;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedEntry;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\Backlinks;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Subentry\SubentryDetector;
use Generator;

/**
 * Scope-filtered list helpers for array-backed stores; composes DefaultHasChildrenTrait (use that directly for DB-backed adapters).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ArrayEntryStorageTrait
{
    use DefaultHasChildrenTrait;

    private SortKeyComparator $sortKeyComparator;

    private LinkedAttributes $linkedAttributes;

    /**
     * @param array<string, Entry> $entries Entries keyed by normalised DN string
     * @param array<string, int> $keys Entry key per normalised DN string
     */
    private function listFromArray(
        StorageListOptions $options,
        array $entries,
        array $keys = [],
    ): EntryStream {
        $scoped = $this->yieldByScope($options, $entries);
        $backlinks = $this->backlinksWanted($options);

        if (!$backlinks->isEmpty()) {
            $scoped = $this->withBacklinks(
                $scoped,
                $this->backlinksIn($entries, $backlinks),
            );
        }
        if ($options->projection->windows !== []) {
            $scoped = $this->slicing($scoped, $options->projection);
        }
        if ($options->projection->withHasSubordinates) {
            $scoped = $this->withChildFlag(
                $scoped,
                $this->parentDnsIn($entries),
            );
        }
        if ($options->sortKeys === []) {
            return EntryStream::positioned($this->pageByKey(
                $scoped,
                $keys,
                $options,
            ));
        }

        /** @var list<Entry> $collected */
        $collected = iterator_to_array(
            $scoped,
            preserve_keys: false,
        );

        return EntryStream::positioned($this->pageByCount(
            $this->sortKeyComparator->sort($collected, $options->sortKeys),
            $options,
        ));
    }

    /**
     * @param iterable<Entry> $entries
     * @return Generator<int, Entry>
     */
    private function slicing(
        iterable $entries,
        EntryProjection $projection,
    ): Generator {
        foreach ($entries as $entry) {
            yield $this->sliced($entry, $projection);
        }
    }

    /**
     * The entry with each attribute a slice was asked of cut down to it and named for what that left.
     */
    private function sliced(
        Entry $entry,
        EntryProjection $projection,
    ): Entry {
        $cap = $projection->linkCap ?? EntryProjection::DEFAULT_LINK_CAP;
        $sliced = $entry->makeCopy();

        foreach ($projection->windows as $name => $window) {
            $held = $sliced->get($name, true);

            if ($held === null) {
                continue;
            }
            $values = array_values($held->getValues());
            $slice = array_slice($values, $window->first, $window->size($cap));
            $sliced->reset($name);

            if ($slice === []) {
                continue;
            }

            $sliced->set(
                $window->nameFor(
                    $name,
                    count($slice),
                    count($values) > $window->first + count($slice),
                ),
                ...$slice,
            );
        }

        return $sliced;
    }

    /**
     * The back-links to derive.
     */
    private function backlinksWanted(StorageListOptions $options): Backlinks
    {
        $wanted = $options->projection->backlinks;

        foreach (FilterAttributes::referenced($options->filter) ?? [] as $attribute) {
            $wanted[] = $attribute;
        }

        return $this->linkedAttributes
            ->backlinks()
            ->only($wanted);
    }

    /**
     * One entry carrying the back-links a read asked for.
     *
     * @param array<string, Entry> $entries
     */
    private function withBacklinksOn(
        Entry $entry,
        EntryProjection $projection,
        array $entries,
    ): Entry {
        $backlinks = $this->linkedAttributes
            ->backlinks()
            ->only($projection->backlinks);

        if ($backlinks->isEmpty()) {
            return $entry;
        }
        $named = $this->backlinksIn($entries, $backlinks);

        foreach ($this->withBacklinks([$entry], $named) as $withBacklinks) {
            return $withBacklinks;
        }

        return $entry;
    }

    /**
     * Which entries each entry is named by.
     *
     * @param array<string, Entry> $entries
     *
     * @return array<string, array<string, list<string>>>
     */
    private function backlinksIn(
        array $entries,
        Backlinks $backlinks,
    ): array {
        $named = [];

        foreach ($backlinks->linkedNames() as $linked) {
            $names = $backlinks->reversing($linked);

            foreach ($this->ownersByTarget($entries, $linked) as $target => $owners) {
                $named[$target] = [
                    ...$named[$target] ?? [],
                    ...array_fill_keys($names, $owners),
                ];
            }
        }

        return $named;
    }

    /**
     * The entries naming each target through one linked attribute.
     *
     * @param array<string, Entry> $entries
     *
     * @return array<string, list<string>> Keyed by the target's normalised DN
     */
    private function ownersByTarget(
        array $entries,
        string $linked,
    ): array {
        $owners = [];

        foreach ($entries as $entry) {
            foreach ($entry->get($linked, true)?->getValues() ?? [] as $value) {
                $target = Dn::normalizedOrNull($value);

                if ($target !== null) {
                    $owners[$target][] = $entry->getDn()->toString();
                }
            }
        }

        return $owners;
    }

    /**
     * @param iterable<Entry> $entries
     * @param array<string, array<string, list<string>>> $named
     * @return Generator<int, Entry>
     */
    private function withBacklinks(
        iterable $entries,
        array $named,
    ): Generator {
        foreach ($entries as $entry) {
            $held = $named[$entry->getDn()->normalizedString()] ?? [];
            if ($held === []) {
                yield $entry;

                continue;
            }
            $copy = $entry->makeCopy();

            foreach ($held as $backlink => $values) {
                $copy->set($backlink, ...$values);
            }

            yield $copy;
        }
    }

    /**
     * The normalised DN of every entry that is some other entry's parent.
     *
     * @param array<string, Entry> $entries
     * @return array<string, true>
     */
    private function parentDnsIn(array $entries): array
    {
        $parents = [];

        foreach ($entries as $entry) {
            $parent = $entry->getDn()
                ->getParent()
                ?->normalizedString();

            if ($parent !== null) {
                $parents[$parent] = true;
            }
        }

        return $parents;
    }

    /**
     * @param iterable<Entry> $entries
     * @param array<string, true> $parents
     * @return Generator<int, Entry>
     */
    private function withChildFlag(
        iterable $entries,
        array $parents,
    ): Generator {
        foreach ($entries as $entry) {
            $flagged = $entry->makeCopy();
            $flagged->set(
                AttributeTypeOid::NAME_HAS_SUBORDINATES,
                isset($parents[$entry->getDn()->normalizedString()]) ? 'TRUE' : 'FALSE',
            );

            yield $flagged;
        }
    }

    /**
     * Hands over the window $options asks for, resuming past the key it names.
     *
     * @param iterable<Entry> $entries
     * @param array<string, int> $keys Entry key per normalised DN string
     * @return Generator<int, FetchedEntry, mixed, FetchedBatch>
     */
    private function pageByKey(
        iterable $entries,
        array $keys,
        StorageListOptions $options,
    ): Generator {
        $after = $options->bounds->resumeAfter()?->position;
        $cursor = $options->bounds->resumeAfter();
        $limit = $options->bounds->limit();
        $taken = 0;
        $hasMore = false;

        foreach ($entries as $entry) {
            $key = $keys[$entry->getDn()->normalizedString()] ?? null;

            if ($after !== null && $key !== null && $key <= $after) {
                continue;
            }

            // Seen but not handed over: its only job is to prove the result did not end here.
            if ($limit !== null && $taken >= $limit) {
                $hasMore = true;

                break;
            }

            $taken++;

            if ($key !== null) {
                $cursor = PageCursor::afterEntry($key);
            }

            yield new FetchedEntry(
                $entry,
                $key !== null
                    ? $cursor
                    : null,
            );
        }

        return new FetchedBatch(
            $taken,
            $cursor,
            $hasMore,
        );
    }

    /**
     * Hands over the window $options asks for, resuming by how much was already delivered.
     *
     * A sort defines its own order that the key says nothing about, so the count is the only position that means
     * anything. The sort is recomputed identically for every page.
     *
     * @param iterable<Entry> $entries
     * @return Generator<int, FetchedEntry, mixed, FetchedBatch>
     */
    private function pageByCount(
        iterable $entries,
        StorageListOptions $options,
    ): Generator {
        $delivered = $options->bounds->resumeAfter()->position ?? 0;
        $limit = $options->bounds->limit();
        $skipped = 0;
        $taken = 0;
        $hasMore = false;

        foreach ($entries as $entry) {
            if ($skipped < $delivered) {
                $skipped++;

                continue;
            }

            if ($limit !== null && $taken >= $limit) {
                $hasMore = true;

                break;
            }

            $taken++;

            yield new FetchedEntry(
                $entry,
                PageCursor::afterSorted($delivered + $taken),
            );
        }

        return new FetchedBatch(
            $taken,
            PageCursor::afterSorted($delivered + $taken),
            $hasMore,
        );
    }

    /**
     * @param array<string, Entry> $entries Entries keyed by normalised DN string
     * @return list<Dn>
     */
    private function namingContextsFromArray(array $entries): array
    {
        $roots = [];
        foreach (array_keys($entries) as $normDn) {
            $normDn = (string) $normDn;
            $parent = (new Dn($normDn))->getParent()?->toString() ?? '';
            if ($parent === '' || !isset($entries[$parent])) {
                $roots[] = new Dn($normDn);
            }
        }

        return $roots;
    }

    /**
     * Entries in scope, in insertion order, which is ascending key order since keys are handed out on insert and a
     * rename re-keys the array in place.
     *
     * @param array<string, Entry> $entries Entries keyed by normalised DN string
     * @return Generator<int, Entry>
     */
    private function yieldByScope(
        StorageListOptions $options,
        array $entries,
    ): Generator {
        $deadline = $options->bounds->deadline;
        $scope = $options->scope;

        foreach ($entries as $normDn => $entry) {
            if ($deadline !== null && microtime(true) >= $deadline) {
                throw new TimeLimitExceededException();
            }

            $entryDn = Dn::fromCanonical((string) $normDn);

            $inScope = $scope->subtree
                ? $entryDn->isDescendantOf($scope->baseDn)
                : $entryDn->isChildOf($scope->baseDn);

            if ($inScope && SubentryDetector::isVisibleUnder($entry, $scope->subentries)) {
                yield $entry;
            }
        }
    }
}
