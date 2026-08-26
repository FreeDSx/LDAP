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
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedBatch;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
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

        if ($options->sortKeys === []) {
            return new EntryStream($this->pageByKey(
                $scoped,
                $keys,
                $options,
            ));
        }

        /** @var list<Entry> $collected */
        $collected = iterator_to_array($scoped, false);

        return new EntryStream($this->pageByCount(
            $this->sortKeyComparator->sort($collected, $options->sortKeys),
            $options,
        ));
    }

    /**
     * Hands over the window $options asks for, resuming past the key it names.
     *
     * @param iterable<Entry> $entries
     * @param array<string, int> $keys Entry key per normalised DN string
     * @return Generator<int, Entry, mixed, FetchedBatch>
     */
    private function pageByKey(
        iterable $entries,
        array $keys,
        StorageListOptions $options,
    ): Generator {
        $after = $options->after?->position;
        $cursor = $options->after;
        $taken = 0;
        $hasMore = false;

        foreach ($entries as $entry) {
            $key = $keys[$entry->getDn()->normalize()->toString()] ?? null;

            if ($after !== null && $key !== null && $key <= $after) {
                continue;
            }

            // Seen but not handed over: its only job is to prove the result did not end here.
            if ($options->maxCandidates !== null && $taken >= $options->maxCandidates) {
                $hasMore = true;

                break;
            }

            $taken++;

            if ($key !== null) {
                $cursor = PageCursor::afterEntry($key);
            }

            yield $entry;
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
     * @return Generator<int, Entry, mixed, FetchedBatch>
     */
    private function pageByCount(
        iterable $entries,
        StorageListOptions $options,
    ): Generator {
        $delivered = $options->after->position ?? 0;
        $skipped = 0;
        $taken = 0;
        $hasMore = false;

        foreach ($entries as $entry) {
            if ($skipped < $delivered) {
                $skipped++;

                continue;
            }

            if ($options->maxCandidates !== null && $taken >= $options->maxCandidates) {
                $hasMore = true;

                break;
            }

            $taken++;

            yield $entry;
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
        $deadline = $options->timeLimit > 0
            ? microtime(true) + $options->timeLimit
            : null;

        foreach ($entries as $normDn => $entry) {
            if ($deadline !== null && microtime(true) >= $deadline) {
                throw new TimeLimitExceededException();
            }

            $entryDn = Dn::fromCanonical((string) $normDn);

            $inScope = $options->subtree
                ? $entryDn->isDescendantOf($options->baseDn)
                : $entryDn->isChildOf($options->baseDn);

            if ($inScope && SubentryDetector::isVisibleUnder($entry, $options->subentries)) {
                yield $entry;
            }
        }
    }
}
