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
 * Cross-platform link SQL shared by every PdoLinkDialectInterface implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoLinkDialectTrait
{
    public function queryLinksForRange(): string
    {
        return <<<SQL
            SELECT l.owner_entry_id, l.attr_name_lower, l.target_uid, e.dn
            FROM entry_attribute_links l
            JOIN entries e ON e.entry_id = l.target_entry_id
            WHERE l.owner_entry_id BETWEEN ? AND ?
            ORDER BY l.owner_entry_id, l.attr_name_lower, l.target_entry_id
        SQL;
    }

    public function queryLinksForRangeUpTo(): string
    {
        return $this->queryLinksForRange() . ' LIMIT ?';
    }

    public function queryOversizedLinks(): string
    {
        return <<<SQL
            SELECT owner_entry_id, attr_name_lower
            FROM entry_attribute_links
            WHERE owner_entry_id BETWEEN ? AND ?
            GROUP BY owner_entry_id, attr_name_lower
            HAVING COUNT(*) > ?
        SQL;
    }

    public function queryLinksForRangeExcept(int $count): string
    {
        $markers = SqlFilterUtility::markers(
            $count,
            '(?, ?)',
        );

        return <<<SQL
            SELECT l.owner_entry_id, l.attr_name_lower, l.target_uid, e.dn
            FROM entry_attribute_links l
            JOIN entries e ON e.entry_id = l.target_entry_id
            WHERE l.owner_entry_id BETWEEN ? AND ?
              AND (l.owner_entry_id, l.attr_name_lower) NOT IN ($markers)
            ORDER BY l.owner_entry_id, l.attr_name_lower, l.target_entry_id
        SQL;
    }

    public function queryLinksForAttribute(): string
    {
        return <<<SQL
            SELECT l.owner_entry_id, l.attr_name_lower, l.target_uid, e.dn
            FROM entry_attribute_links l
            JOIN entries e ON e.entry_id = l.target_entry_id
            WHERE l.owner_entry_id = ? AND l.attr_name_lower = ?
            ORDER BY l.target_entry_id
            LIMIT ?
        SQL;
    }
}
