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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract;

use PDOException;

/**
 * Database-specific SQL for writing the entry table.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoEntryWriteDialectInterface
{
    /**
     * Whether the failure is the unique key on lc_dn refusing a second entry at one DN.
     */
    public function isDuplicateEntry(PDOException $exception): bool;

    /**
     * Whether the failure is a value exceeding its column's declared length.
     */
    public function isValueTooLong(PDOException $exception): bool;

    /**
     * The longest DN in bytes the database can store, or null when there is no practical limit.
     */
    public function maxDnLength(): ?int;

    /**
     * The key of the entry at the DN. Parameters: [lc_dn]
     */
    public function queryEntryId(): string;

    /**
     * Insert or replace one entry. Parameters: [lc_dn, dn, lc_parent_dn, attributes]
     */
    public function queryUpsert(): string;

    /**
     * Insert one entry, failing when the DN is taken. Parameters: [lc_dn, dn, lc_parent_dn, attributes]
     */
    public function queryInsert(): string;

    /**
     * Re-key one entry in place. Parameters: [dn, lc_dn, lc_parent_dn, current lc_dn]
     */
    public function queryRenameEntry(): string;

    /**
     * Re-key every entry beneath a DN, keeping each stored DN's own spelling of its leading RDNs.
     */
    public function queryRenameDescendants(): string;

    /**
     * Delete the entry at the DN. Parameters: [lc_dn]
     */
    public function queryDelete(): string;

    /**
     * Delete the entries at $count DNs. Parameters: [lc_dn, ...]
     */
    public function queryDeleteIn(int $count): string;
}
