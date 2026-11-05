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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\LinkKeys;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;

/**
 * Cross-platform link read SQL shared by every PdoLinkReadDialectInterface implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoLinkReadDialectTrait
{
    public function queryLinksFor(LinkKeys $owners): string
    {
        $covered = $owners->condition('l.owner_entry_id');

        return <<<SQL
            SELECT l.owner_entry_id AS key_entry_id, l.attr_name_lower, e.dn
            FROM entry_attribute_links l
            JOIN entries e ON e.entry_id = l.target_entry_id
            WHERE $covered
            ORDER BY l.owner_entry_id, l.attr_name_lower, l.target_entry_id
        SQL;
    }

    public function queryLinksForUpTo(LinkKeys $owners): string
    {
        return $this->queryLinksFor($owners) . ' LIMIT ?';
    }

    public function queryOversizedLinks(LinkKeys $owners): string
    {
        $covered = $owners->condition('owner_entry_id');

        return <<<SQL
            SELECT owner_entry_id AS key_entry_id, attr_name_lower
            FROM entry_attribute_links
            WHERE $covered
            GROUP BY owner_entry_id, attr_name_lower
            HAVING COUNT(*) > ?
        SQL;
    }

    public function queryLinksForExcept(
        LinkKeys $owners,
        int $count,
    ): string {
        $covered = $owners->condition('l.owner_entry_id');
        $markers = SqlFilterUtility::markers(
            $count,
            '(?, ?)',
        );

        return <<<SQL
            SELECT l.owner_entry_id AS key_entry_id, l.attr_name_lower, e.dn
            FROM entry_attribute_links l
            JOIN entries e ON e.entry_id = l.target_entry_id
            WHERE $covered
              AND (l.owner_entry_id, l.attr_name_lower) NOT IN ($markers)
            ORDER BY l.owner_entry_id, l.attr_name_lower, l.target_entry_id
        SQL;
    }

    public function queryHeldLinkValues(int $count): string
    {
        $markers = SqlFilterUtility::markers($count);

        return <<<SQL
            SELECT t.lc_dn
            FROM entry_attribute_links l
            JOIN entries o ON o.entry_id = l.owner_entry_id
            JOIN entries t ON t.entry_id = l.target_entry_id
            WHERE o.lc_dn = ? AND l.attr_name_lower = ? AND t.lc_dn IN ($markers)
        SQL;
    }

    public function queryAnyLinkValue(): string
    {
        return <<<SQL
            SELECT t.dn
            FROM entry_attribute_links l
            JOIN entries o ON o.entry_id = l.owner_entry_id
            JOIN entries t ON t.entry_id = l.target_entry_id
            WHERE o.lc_dn = ? AND l.attr_name_lower = ?
            LIMIT 1
        SQL;
    }

    public function queryLinksForAttribute(): string
    {
        return <<<SQL
            SELECT l.owner_entry_id AS key_entry_id, l.attr_name_lower, e.dn
            FROM entry_attribute_links l
            JOIN entries e ON e.entry_id = l.target_entry_id
            WHERE l.owner_entry_id = ? AND l.attr_name_lower = ?
            ORDER BY l.target_entry_id
            LIMIT ?
        SQL;
    }

    public function queryLinksForAttributeFrom(): string
    {
        return $this->queryLinksForAttribute() . ' OFFSET ?';
    }
}
