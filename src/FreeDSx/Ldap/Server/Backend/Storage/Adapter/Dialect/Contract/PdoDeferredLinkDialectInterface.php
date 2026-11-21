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

/**
 * Database-specific SQL for linked values held back from a write until the entries they name are placed.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoDeferredLinkDialectInterface
{
    /**
     * The storage key of the entry holding an entryUUID.
     *
     * Parameters: [entry_uuid]
     */
    public function queryEntryIdByUuid(): string;

    /**
     * Discards the values held back for an owner.
     *
     * Parameters: [owner_entry_id]
     */
    public function queryDeleteDeferredForOwner(): string;

    /**
     * Discards the values held back for the entry holding an entryUUID.
     *
     * Parameters: [entry_uuid]
     */
    public function queryDeleteDeferredForEntryUuid(): string;

    /**
     * INSERT of $count held back values.
     *
     * Parameters: [owner_entry_id, attr_name_lower, target_value per value]
     */
    public function queryInsertDeferred(int $count): string;

    /**
     * The owners of the first held back values with how many of those each holds, lowest storage key first.
     *
     * Parameters: [limit]
     */
    public function queryDeferredOwners(): string;

    /**
     * The values held back for an owner.
     *
     * Parameters: [owner_entry_id]
     */
    public function queryDeferredForOwner(): string;

    /**
     * Discards the values held back for $count owners.
     *
     * Parameters: [owner_entry_id per owner]
     */
    public function queryDeleteDeferredForOwners(int $count): string;
}
