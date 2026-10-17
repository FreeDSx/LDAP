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

namespace FreeDSx\Ldap\Server\Backend\Storage\Directory;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use Generator;

use function array_filter;
use function array_flip;
use function array_values;

/**
 * Reads what sits beneath a DN, in the shape the caller needs it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SubtreeEnumerator
{
    /**
     * Children read at a time while walking a subtree.
     */
    private const PAGE_SIZE = 500;

    public function __construct(
        private ReadEntryInterface $reader,
        private ListEntryInterface $lister,
    ) {}

    /**
     * Every entry after all of its children, read a page at a time, so no prefix of it strands a child of what it holds.
     *
     * @return Generator<int, string> canonical DNs, ending with the base
     */
    public function leavesFirst(Dn $base): Generator
    {
        yield from $this->childrenFirst($base->normalizedString());
    }

    /**
     * Children of the entries that are not themselves among them, which removing the entries would strand.
     *
     * @param list<string> $dns canonical DNs
     *
     * @return list<string>
     */
    public function childrenOutside(array $dns): array
    {
        $members = array_flip($dns);

        return array_values(array_filter(
            $this->lister->childDns($dns),
            static fn(string $child): bool => !isset($members[$child]),
        ));
    }

    /**
     * Read in full rather than streamed, so writes by the caller do not run against an open result set.
     *
     * @return list<Entry> everything beneath the base, excluding the base itself
     */
    public function descendantsOf(Dn $base): array
    {
        $descendants = [];
        $options = StorageListOptions::matchAll(
            $base,
            subtree: true,
        );

        foreach ($this->lister->list($options)->entries() as $entry) {
            if ($entry->getDn()->normalizedString() !== $base->toString()) {
                $descendants[] = $entry;
            }
        }

        return $descendants;
    }

    /**
     * @param list<Dn> $dnList
     *
     * @return list<Entry> those that still exist, in the order given
     */
    public function entriesAt(array $dnList): array
    {
        $entries = [];
        foreach ($dnList as $dn) {
            // Removing an entry takes its links with it, so journaling them would only record what is already gone.
            $entry = $this->reader->find(
                $dn,
                new EntryProjection(linkCap: 0),
            );
            if ($entry !== null) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * @return Generator<int, string>
     */
    private function childrenFirst(string $dn): Generator
    {
        foreach ($this->children($dn) as [$child, $hasChildren]) {
            if ($hasChildren) {
                yield from $this->childrenFirst($child);

                continue;
            }

            yield $child;
        }

        yield $dn;
    }

    /**
     * @return Generator<int, array{string, bool}> each child with whether it has children of its own
     */
    private function children(string $parent): Generator
    {
        $after = null;

        do {
            [$page, $after] = $this->childPage(
                $parent,
                $after,
            );

            yield from $page;
        } while ($after !== null);
    }

    /**
     * Read to its end before any child is handed on, so writes by the caller never run against an open result set.
     *
     * @return array{list<array{string, bool}>, ?PageCursor} the page, and where the next one starts when there is one
     */
    private function childPage(
        string $parent,
        ?PageCursor $after,
    ): array {
        $fetched = $this->lister->list(StorageListOptions::forChildPage(
            Dn::fromCanonical($parent),
            self::PAGE_SIZE,
            $after,
        ))->fetched();

        $children = [];
        foreach ($fetched as $child) {
            $children[] = [
                $child->entry->getDn()->normalizedString(),
                $child->entry->get(AttributeTypeOid::NAME_HAS_SUBORDINATES)?->getValues() === ['TRUE'],
            ];
        }
        $batch = $fetched->getReturn();

        return [
            $children,
            $batch === null || $batch->isExhausted()
                ? null
                : $batch->cursor,
        ];
    }
}
