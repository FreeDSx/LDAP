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
 * Cross-platform link write SQL shared by every {@see PdoLinkWriteDialectInterface} implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoLinkWriteDialectTrait
{
    public function queryLinkIdsForOwner(): string
    {
        return <<<SQL
            SELECT attr_name_lower, target_entry_id, target_uid
            FROM entry_attribute_links
            WHERE owner_entry_id = ?
        SQL;
    }

    public function queryResolveDns(int $count): string
    {
        $markers = SqlFilterUtility::markers($count);

        return <<<SQL
            SELECT entry_id, lc_dn
            FROM entries
            WHERE lc_dn IN ($markers)
        SQL;
    }

    public function queryInsertLinks(int $count): string
    {
        $rows = SqlFilterUtility::markers(
            $count,
            '(?, ?, ?, ?)',
        );

        return <<<SQL
            INSERT INTO entry_attribute_links (owner_entry_id, attr_name_lower, target_entry_id, target_uid)
            VALUES $rows
        SQL;
    }

    public function queryDeleteLinks(int $count): string
    {
        $keys = SqlFilterUtility::markers(
            $count,
            '(?, ?, ?)',
        );

        return <<<SQL
            DELETE FROM entry_attribute_links
            WHERE owner_entry_id = ?
              AND (attr_name_lower, target_entry_id, target_uid) IN ($keys)
        SQL;
    }
}
