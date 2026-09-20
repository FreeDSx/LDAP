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
 * Database-specific SQL for values naming an entry that is not stored yet.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoPendingLinkDialectInterface
{
    /**
     * Discards everything an owner had parked, since a write restates which of its values are unresolved.
     *
     * Parameters: [owner_entry_id]
     */
    public function queryDeletePendingForOwner(): string;

    /**
     * INSERT of $count parked values.
     *
     * Parameters: [owner_entry_id, attr_name_lower, target_lc_dn, target_value, target_uid per value]
     */
    public function queryInsertPending(int $count): string;

    /**
     * Links every parked value whose target is now stored, skipping any that is already linked.
     *
     * Parameters: [target_lc_dn] when true, none otherwise.
     *
     * @param bool $byDn Limit to one newly stored DN.
     */
    public function queryPromotePending(bool $byDn): string;

    /**
     * Clears the parked values {@see queryPromotePending()} has just linked.
     *
     * Parameters: [target_lc_dn] when true, none otherwise.
     *
     * @param bool $byDn Limit to one newly stored DN.
     */
    public function queryDeletePromotedPending(bool $byDn): string;

    /**
     * The attribute names an owner has parked values for.
     *
     * Parameters: [owner_entry_id]
     */
    public function queryPendingNamesForOwner(): string;

    /**
     * Returns a row when anything is parked, which is what promotion checks before doing any work.
     *
     * Parameters: [target_lc_dn] when true, none otherwise.
     *
     * @param bool $byDn Limit to one stored DN.
     */
    public function queryAnyPending(bool $byDn = false): string;
}
