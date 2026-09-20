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
 * Database-specific SQL for writing the table linked attribute values are kept in.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoLinkWriteDialectInterface
{
    /**
     * One owner's links as the keys a write diffs on.
     *
     * Parameters: [owner_entry_id]
     */
    public function queryLinkIdsForOwner(): string;

    /**
     * The ids of $count normalised DNs, which is how a value becomes a link.
     *
     * Parameters: [lc_dn, ...]
     */
    public function queryResolveDns(int $count): string;

    /**
     * INSERT of $count links.
     *
     * Parameters: [owner_entry_id, attr_name_lower, target_entry_id, target_uid per link]
     */
    public function queryInsertLinks(int $count): string;

    /**
     * DELETE of $count of one owner's links.
     *
     * Parameters: [owner_entry_id, then attr_name_lower, target_entry_id, target_uid per link]
     */
    public function queryDeleteLinks(int $count): string;
}
