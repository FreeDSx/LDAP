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

namespace FreeDSx\Ldap\Server\Backend\Storage\Capability;

use FreeDSx\Ldap\Entry\Dn;

/**
 * A storage adapter that can take a per-entry lock inside an atomic block.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface RowLockableInterface
{
    /**
     * Exclusively lock the entries, in one global order, until the atomic block ends.
     *
     * @param list<Dn> $dns
     *
     * @return list<Dn> the entries now held, which leaves out any that were not there to lock
     */
    public function lockForWrite(array $dns): array;

    /**
     * Hold the entry against deletion for the rest of the atomic block.
     *
     * A shared lock so entries may be written beneath one parent concurrently while a delete of that parent waits.
     *
     * @return bool whether it was there to hold
     */
    public function lockForReference(Dn $dn): bool;
}
