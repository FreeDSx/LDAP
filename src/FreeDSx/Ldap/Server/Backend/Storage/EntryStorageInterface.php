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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\DefaultHasChildrenTrait;
use Generator;

/**
 * Primitive storage contract for directory entries.
 *
 * Implementations handle raw data persistence only — all LDAP semantics (validation, error codes, scope checking) are
 * handled by WritableStorageBackend.
 *
 * Where methods accept a Dn parameter, it is a normalised (lowercased) Dn as returned by Dn::normalize(). Use
 * $dn->toString() as the internal string key.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface EntryStorageInterface
{
    /**
     * Return the entry for the given normalised DN, or null if not found.
     */
    public function find(Dn $dn): ?Entry;

    /**
     * Return true if the given normalised DN has any direct children.
     *
     * Implementations may use {@see DefaultHasChildrenTrait} for a default implementation built on top of list().
     * Backends that can answer more efficiently (e.g. an EXISTS query on a database) should override it directly.
     */
    public function hasChildren(Dn $dn): bool;

    /**
     * Yield entries rooted at $baseDn.
     *
     * When $subtree is false: yield only direct children (base entry not included).
     * When $subtree is true: yield all entries whose DN matches or is subordinate to $baseDn.
     *
     * Pass a Dn with an empty string to list from the root of the tree.
     *
     * Implementations should stream entries lazily where possible to avoid
     * loading the entire dataset into memory at once.
     *
     * @return Generator<Entry>
     */
    public function list(
        Dn $baseDn,
        bool $subtree
    ): Generator;

    /**
     * Persist the entry, replacing any existing entry at the same DN.
     *
     * The entry must be keyed by its normalised DN. Use $entry->getDn()->normalize()->toString() as the storage key,
     * as the Entry's own DN may retain the original client-supplied casing.
     */
    public function store(Entry $entry): void;

    /**
     * Remove the entry for the given normalised DN. A no-op if the entry does not exist.
     */
    public function remove(Dn $dn): void;

    /**
     * Execute $operation as an atomic read-modify-write cycle.
     *
     * Implementations backed by a file, database, or any resource accessible to concurrent connections must acquire
     * an appropriate lock or open a transaction before executing $operation, then commit or release on completion.
     *
     * @param callable(EntryStorageInterface): void $operation
     */
    public function atomic(callable $operation): void;
}
