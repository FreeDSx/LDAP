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
 * Cross-platform SQL for held back link values, shared by every {@see PdoDeferredLinkDialectInterface} implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoDeferredLinkDialectTrait
{
    public function queryEntryIdByUuid(): string
    {
        return <<<SQL
            SELECT entry_id
            FROM entries
            WHERE entry_uuid = ?
        SQL;
    }

    public function queryDeleteDeferredForOwner(): string
    {
        return <<<SQL
            DELETE FROM entry_link_deferred
            WHERE owner_entry_id = ?
        SQL;
    }

    public function queryDeleteDeferredForEntryUuid(): string
    {
        return <<<SQL
            DELETE FROM entry_link_deferred
            WHERE owner_entry_id = (SELECT entry_id FROM entries WHERE entry_uuid = ?)
        SQL;
    }

    public function queryInsertDeferred(int $count): string
    {
        $rows = SqlFilterUtility::markers(
            $count,
            '(?, ?, ?)',
        );

        return <<<SQL
            INSERT INTO entry_link_deferred (owner_entry_id, attr_name_lower, target_value)
            VALUES $rows
        SQL;
    }

    public function queryDeferredOwners(): string
    {
        return <<<SQL
            SELECT owner_entry_id, COUNT(*) AS held
            FROM (
                SELECT owner_entry_id
                FROM entry_link_deferred
                ORDER BY owner_entry_id
                LIMIT ?
            ) AS next_held
            GROUP BY owner_entry_id
            ORDER BY owner_entry_id
        SQL;
    }

    public function queryDeferredForOwner(): string
    {
        return <<<SQL
            SELECT attr_name_lower, target_value
            FROM entry_link_deferred
            WHERE owner_entry_id = ?
        SQL;
    }

    public function queryDeleteDeferredForOwners(int $count): string
    {
        $owners = SqlFilterUtility::markers($count);

        return <<<SQL
            DELETE FROM entry_link_deferred
            WHERE owner_entry_id IN ($owners)
        SQL;
    }
}
