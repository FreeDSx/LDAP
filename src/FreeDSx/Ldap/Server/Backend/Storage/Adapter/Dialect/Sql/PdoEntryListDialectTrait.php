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

use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SortedQuery;

use function strtolower;

/**
 * Cross-platform entry list SQL shared by every PdoEntryListDialectInterface implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoEntryListDialectTrait
{
    public function queryFetchAll(bool $withChildFlag = false): string
    {
        $columns = $this->listColumns() . $this->childFlagColumn($withChildFlag, 'entries');

        return <<<SQL
            SELECT {$columns}
            FROM entries
        SQL;
    }

    public function queryFetchChildren(bool $withChildFlag = false): string
    {
        $columns = $this->listColumns() . $this->childFlagColumn($withChildFlag, 'entries');

        return <<<SQL
            SELECT {$columns}
            FROM entries
            WHERE lc_parent_dn = ?
        SQL;
    }

    public function querySubtree(bool $withChildFlag = false): string
    {
        $columns = $this->listColumns() . $this->childFlagColumn($withChildFlag, 'subtree');

        return <<<SQL
            WITH RECURSIVE subtree AS (
                SELECT entry_id, lc_dn, dn, attributes
                FROM entries
                WHERE lc_dn = ?
                UNION ALL
                SELECT e.entry_id, e.lc_dn, e.dn, e.attributes
                FROM entries e
                INNER JOIN subtree s ON e.lc_parent_dn = s.lc_dn
            )
            SELECT {$columns} FROM subtree
        SQL;
    }

    public function querySubentryCondition(
        string $dnColumn,
        bool $exclude,
    ): string {
        $operator = $exclude
            ? 'NOT IN'
            : 'IN';
        $objectClass = strtolower(AttributeTypeOid::NAME_OBJECT_CLASS);
        $subentry = strtolower(ObjectClassOid::NAME_SUBENTRY);

        return <<<SQL
            $dnColumn $operator (
                SELECT sub.owner_entry_id
                FROM entry_attribute_values sub
                WHERE sub.attr_name_lower = '$objectClass'
                  AND sub.value_lower = '$subentry'
            )
        SQL;
    }

    public function sortedQuery(
        string $baseSql,
        array $baseParams,
        array $sortKeys,
    ): SortedQuery {
        $projections = [];
        $orderTerms = [];
        $sortParams = [];

        // MySQL/MariaDB lack NULLS FIRST/LAST and would re-run the correlated subquery per ORDER BY term; project the
        // key once into a derived table, then order by the materialised column (single evaluation per candidate).
        foreach ($sortKeys as $index => $sortKey) {
            $alias = '__sk' . $index;
            $value = $sortKey->numeric
                ? 'CAST(eav.value_lower AS SIGNED)'
                : 'eav.value_lower';
            $projections[] = <<<SQL
                (SELECT MIN({$value})
                 FROM entry_attribute_values eav
                 WHERE eav.owner_entry_id = __base.entry_id
                   AND eav.attr_name_lower = ?) AS {$alias}
                SQL;
            $orderTerms[] = "{$alias} IS NULL {$sortKey->direction}, {$alias} {$sortKey->direction}";
            $sortParams[] = $sortKey->attributeLower;
        }

        $projection = implode(",\n", $projections);
        $order = implode(', ', $orderTerms);
        $sql = <<<SQL
            SELECT entry_id, dn, attributes FROM (
                SELECT __base.entry_id, __base.dn, __base.attributes,
                {$projection}
                FROM ({$baseSql}) __base
            ) __keyed
            ORDER BY {$order}
            SQL;

        // The projected subqueries precede the nested base query textually.
        // So their params bind first.
        return new SortedQuery(
            $sql,
            array_merge(
                $sortParams,
                $baseParams,
            ),
        );
    }

    /**
     * Correlated against the row being returned.
     */
    protected function childFlagColumn(
        bool $withChildFlag,
        string $outerTable,
    ): string {
        if (!$withChildFlag) {
            return '';
        }

        return <<<SQL
            , EXISTS (
                SELECT 1
                FROM entries child
                WHERE child.lc_parent_dn = {$outerTable}.lc_dn) AS has_children
            SQL;
    }

    /**
     * Columns every list query selects; the portable sort projects entry_id so it can correlate on the entry key.
     */
    protected function listColumns(): string
    {
        return 'entry_id, lc_dn, dn, attributes';
    }
}
