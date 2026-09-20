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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;

/**
 * Cross-platform SQL for parked link values, shared by every {@see PdoPendingLinkDialectInterface} implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoPendingLinkDialectTrait
{
    public function queryDeletePendingForOwner(): string
    {
        return <<<SQL
            DELETE FROM entry_link_pending
            WHERE owner_entry_id = ?
        SQL;
    }

    public function queryInsertPending(int $count): string
    {
        $rows = SqlFilterUtility::markers(
            $count,
            '(?, ?, ?, ?, ?)',
        );

        return <<<SQL
            INSERT INTO entry_link_pending (owner_entry_id, attr_name_lower, target_lc_dn, target_value, target_uid)
            VALUES $rows
        SQL;
    }

    /**
     * NOT EXISTS rather than an ignore clause, which is spelled differently on every engine.
     */
    public function queryPromotePending(bool $byDn): string
    {
        $limit = $byDn
            ? 'p.target_lc_dn = ? AND'
            : '';

        return <<<SQL
            INSERT INTO entry_attribute_links (owner_entry_id, attr_name_lower, target_entry_id, target_uid)
            SELECT p.owner_entry_id, p.attr_name_lower, e.entry_id, p.target_uid
            FROM entry_link_pending p
            JOIN entries e ON e.lc_dn = p.target_lc_dn
            WHERE $limit NOT EXISTS (
                SELECT 1 FROM entry_attribute_links l
                WHERE l.owner_entry_id = p.owner_entry_id
                  AND l.attr_name_lower = p.attr_name_lower
                  AND l.target_entry_id = e.entry_id
                  AND l.target_uid = p.target_uid
              )
        SQL;
    }

    public function queryDeletePromotedPending(bool $byDn): string
    {
        $limit = $byDn
            ? 'target_lc_dn = ? AND'
            : '';

        return <<<SQL
            DELETE FROM entry_link_pending
            WHERE $limit target_lc_dn IN (SELECT lc_dn FROM entries)
        SQL;
    }

    public function queryPendingNamesForOwner(): string
    {
        return <<<SQL
            SELECT DISTINCT attr_name_lower
            FROM entry_link_pending
            WHERE owner_entry_id = ?
        SQL;
    }

    public function queryAnyPending(): string
    {
        return <<<SQL
            SELECT 1 FROM entry_link_pending LIMIT 1
        SQL;
    }
}
