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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\DefaultHasChildrenTrait;

/**
 * Raw persistence contract; LDAP semantics live in WritableStorageBackend. Dn parameters are always normalised (lowercased).
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
     * Return true if an entry with the given normalised DN exists.
     */
    public function exists(Dn $dn): bool;

    /**
     * Return true if the DN has any direct children; {@see DefaultHasChildrenTrait} supplies a list()-based default.
     */
    public function hasChildren(Dn $dn): bool;

    /**
     * Lazily yield entries per $options scope: direct children when subtree is false, descendants (including base) when true; empty baseDn lists from the tree root.
     */
    public function list(StorageListOptions $options): EntryStream;

    /**
     * Persist the entry keyed by its normalised DN, replacing any existing entry at the same DN.
     */
    public function store(Entry $entry): void;

    /**
     * Remove the entry for the given normalised DN. A no-op if the entry does not exist.
     */
    public function remove(Dn $dn): void;

    /**
     * Execute $operation as an atomic read-modify-write cycle; implementations must hold an exclusive lock or transaction.
     *
     * @param callable(EntryStorageInterface): void $operation
     */
    public function atomic(callable $operation): void;
}
