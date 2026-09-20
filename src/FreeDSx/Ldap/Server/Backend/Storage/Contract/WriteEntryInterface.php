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

namespace FreeDSx\Ldap\Server\Backend\Storage\Contract;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\EntryAlreadyExistsException;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;

/**
 * Persists entries. Dn parameters are always normalised (lowercased).
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface WriteEntryInterface
{
    /**
     * Persist the entry keyed by its normalised DN, replacing any existing entry at the same DN.
     *
     * @param bool $rebuildIndexes Rewrite every secondary-index row rather than only those whose values changed.
     * @param LinkDelta $links Linked values to add and remove, for an attribute the entry no longer carries whole.
     */
    public function store(
        Entry $entry,
        bool $rebuildIndexes = false,
        LinkDelta $links = new LinkDelta(),
    ): void;

    /**
     * Persist the entry only if its normalised DN is free (handles concurrency races).
     *
     * @throws EntryAlreadyExistsException when the DN is taken.
     */
    public function insert(Entry $entry): void;

    /**
     * Re-key the entry at $from and every descendant under $to, leaving attributes and secondary-index rows untouched.
     *
     * $to must be free, its parent must exist, and $to may not sit at or under $from.
     */
    public function renameSubtree(
        Dn $from,
        Dn $to,
    ): void;

    /**
     * Remove the entry for the given normalised DN. A no-op if the entry does not exist.
     */
    public function remove(Dn $dn): void;

    /**
     * Remove every given entry, ignoring any that are already gone.
     *
     * @param list<Dn> $dns
     */
    public function removeAll(array $dns): void;
}
