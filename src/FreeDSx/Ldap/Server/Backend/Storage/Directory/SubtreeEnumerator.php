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
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

use function usort;

/**
 * Reads what sits beneath a DN, in the shape the caller needs it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SubtreeEnumerator
{
    public function __construct(private EntryStorageInterface $storage) {}

    /**
     * Deepest first, so a chunked delete never removes a parent before its children.
     *
     * @return list<Dn> the base and every descendant
     */
    public function dnListDeepestFirst(Dn $base): array
    {
        $options = StorageListOptions::matchAll(
            $base,
            subtree: true,
            attributes: [],
        );

        $dnList = [];
        foreach ($this->storage->list($options)->entries() as $entry) {
            $dnList[] = $entry->getDn()->normalize();
        }
        usort(
            $dnList,
            static fn(Dn $a, Dn $b): int => $b->count() <=> $a->count(),
        );

        return $dnList;
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

        foreach ($this->storage->list($options)->entries() as $entry) {
            if ($entry->getDn()->normalize()->toString() !== $base->toString()) {
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
            $entry = $this->storage->find($dn);
            if ($entry !== null) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }
}
