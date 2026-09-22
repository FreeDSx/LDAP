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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\InvalidAttributeException;

use function implode;
use function sprintf;

/**
 * Cross-platform back-link read SQL shared by every {@see PdoBacklinkReadDialectInterface} implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoBacklinkReadDialectTrait
{
    public function queryBacklinksForRange(array $names): string
    {
        $named = $this->namedAttributes($names);

        return <<<SQL
            SELECT l.target_entry_id AS key_entry_id, l.attr_name_lower, e.dn
            FROM entry_attribute_links l
            JOIN entries e ON e.entry_id = l.owner_entry_id
            WHERE l.target_entry_id BETWEEN ? AND ?
              AND l.attr_name_lower IN ($named)
            ORDER BY l.target_entry_id, l.attr_name_lower, l.owner_entry_id
        SQL;
    }

    public function queryBacklinksForRangeUpTo(array $names): string
    {
        return $this->queryBacklinksForRange($names) . ' LIMIT ?';
    }

    public function queryOversizedBacklinks(array $names): string
    {
        $named = $this->namedAttributes($names);

        return <<<SQL
            SELECT target_entry_id AS key_entry_id, attr_name_lower
            FROM entry_attribute_links
            WHERE target_entry_id BETWEEN ? AND ?
              AND attr_name_lower IN ($named)
            GROUP BY target_entry_id, attr_name_lower
            HAVING COUNT(*) > ?
        SQL;
    }

    public function queryBacklinksForRangeExcept(
        array $names,
        int $count,
    ): string {
        $named = $this->namedAttributes($names);
        $markers = SqlFilterUtility::markers(
            $count,
            '(?, ?)',
        );

        return <<<SQL
            SELECT l.target_entry_id AS key_entry_id, l.attr_name_lower, e.dn
            FROM entry_attribute_links l
            JOIN entries e ON e.entry_id = l.owner_entry_id
            WHERE l.target_entry_id BETWEEN ? AND ?
              AND l.attr_name_lower IN ($named)
              AND (l.target_entry_id, l.attr_name_lower) NOT IN ($markers)
            ORDER BY l.target_entry_id, l.attr_name_lower, l.owner_entry_id
        SQL;
    }

    public function queryBacklinksForAttribute(): string
    {
        return <<<SQL
            SELECT l.target_entry_id AS key_entry_id, l.attr_name_lower, e.dn
            FROM entry_attribute_links l
            JOIN entries e ON e.entry_id = l.owner_entry_id
            WHERE l.target_entry_id = ? AND l.attr_name_lower = ?
            ORDER BY l.owner_entry_id
            LIMIT ?
        SQL;
    }

    public function queryBacklinksForAttributeFrom(): string
    {
        return $this->queryBacklinksForAttribute() . ' OFFSET ?';
    }

    public function queryHeldBacklinkValues(int $count): string
    {
        $markers = SqlFilterUtility::markers($count);

        return <<<SQL
            SELECT o.lc_dn
            FROM entry_attribute_links l
            JOIN entries t ON t.entry_id = l.target_entry_id
            JOIN entries o ON o.entry_id = l.owner_entry_id
            WHERE t.lc_dn = ? AND l.attr_name_lower = ? AND o.lc_dn IN ($markers)
        SQL;
    }

    public function queryAnyBacklinkValue(): string
    {
        return <<<SQL
            SELECT o.dn
            FROM entry_attribute_links l
            JOIN entries t ON t.entry_id = l.target_entry_id
            JOIN entries o ON o.entry_id = l.owner_entry_id
            WHERE t.lc_dn = ? AND l.attr_name_lower = ?
            LIMIT 1
        SQL;
    }

    /**
     * @param list<string> $names
     *
     * @throws InvalidAttributeException
     */
    private function namedAttributes(array $names): string
    {
        $quoted = [];

        foreach ($names as $name) {
            if (!Attribute::isValidDescription($name)) {
                throw new InvalidAttributeException(sprintf(
                    'Attribute description "%s" is not a valid RFC 4512 attribute description.',
                    $name,
                ));
            }
            $quoted[] = sprintf(
                "'%s'",
                Attribute::normalizeName($name),
            );
        }

        return implode(', ', $quoted);
    }
}
