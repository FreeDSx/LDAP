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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\DefaultHasChildrenTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;

/**
 * Reads one entry at a time, or the facts about one. Dn parameters are always normalised (lowercased).
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ReadEntryInterface
{
    /**
     * Return the entry for the given normalised DN, or null if not found; linked values are bounded unless asked otherwise.
     */
    public function find(
        Dn $dn,
        EntryProjection $projection = new EntryProjection(),
    ): ?Entry;

    /**
     * Return true if an entry with the given normalised DN exists.
     */
    public function exists(Dn $dn): bool;

    /**
     * Return true if the DN has any direct children; {@see DefaultHasChildrenTrait} supplies a list()-based default.
     */
    public function hasChildren(Dn $dn): bool;

    /**
     * Normalised DNs of entries whose parent is not in storage. Advertised by the server as RootDSE namingContexts.
     *
     * @return list<Dn>
     */
    public function namingContexts(): array;
}
