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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

use PDO;

/**
 * Standard SQL that should be cross-platform across the adapters.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoDialectTrait
{
    public function beginTransaction(PDO $pdo): void
    {
        $pdo->beginTransaction();
    }

    public function commit(PDO $pdo): void
    {
        $pdo->commit();
    }

    public function rollBack(PDO $pdo): void
    {
        $pdo->rollBack();
    }

    /**
     * Default no-op: SQLite already holds the write lock from `BEGIN IMMEDIATE`, so no per-row lock is needed.
     */
    public function lockRowForWrite(
        PDO $pdo,
        string $table,
        string $lcDn,
    ): void {}

    public function queryExists(): string
    {
        return <<<SQL
            SELECT 1
            FROM entries
            WHERE lc_dn = ?
            LIMIT 1
        SQL;
    }

    public function queryFetchEntry(): string
    {
        return <<<SQL
            SELECT dn, attributes
            FROM entries
            WHERE lc_dn = ?
        SQL;
    }

    public function queryFetchAll(): string
    {
        return <<<SQL
            SELECT {$this->listColumns()}
            FROM entries
        SQL;
    }

    public function queryFetchChildren(): string
    {
        return <<<SQL
            SELECT {$this->listColumns()}
            FROM entries
            WHERE lc_parent_dn = ?
        SQL;
    }

    public function querySubtree(): string
    {
        return <<<SQL
            WITH RECURSIVE subtree AS (
                SELECT lc_dn, dn, attributes
                FROM entries
                WHERE lc_dn = ?
                UNION ALL
                SELECT e.lc_dn, e.dn, e.attributes
                FROM entries e
                INNER JOIN subtree s ON e.lc_parent_dn = s.lc_dn
            )
            SELECT {$this->listColumns()} FROM subtree
        SQL;
    }

    public function queryHasChildren(): string
    {
        return <<<SQL
            SELECT 1
            FROM entries
            WHERE lc_parent_dn = ?
            LIMIT 1
        SQL;
    }

    public function queryNamingContexts(): string
    {
        return <<<SQL
            SELECT dn
            FROM entries
            WHERE lc_parent_dn = ''
               OR lc_parent_dn NOT IN (SELECT lc_dn FROM entries)
        SQL;
    }

    public function queryDelete(): string
    {
        return <<<SQL
            DELETE FROM entries
            WHERE lc_dn = ?
        SQL;
    }

    public function queryDeleteIn(int $count): string
    {
        $markers = implode(
            ', ',
            array_fill(0, $count, '?'),
        );

        return <<<SQL
            DELETE FROM entries
            WHERE lc_dn IN ($markers)
        SQL;
    }

    public function querySidecarDelete(): string
    {
        return <<<SQL
            DELETE FROM entry_attribute_values
            WHERE entry_lc_dn = ?
        SQL;
    }

    public function querySidecarDeleteNames(int $count): string
    {
        $markers = implode(
            ', ',
            array_fill(0, $count, '?'),
        );

        return <<<SQL
            DELETE FROM entry_attribute_values
            WHERE entry_lc_dn = ?
              AND attr_name_lower IN ($markers)
        SQL;
    }

    public function querySidecarInsertPrefix(): string
    {
        return 'INSERT INTO entry_attribute_values (entry_lc_dn, attr_name_lower, value_lower, value_original) VALUES ';
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
            $projections[] = <<<SQL
                (SELECT MIN(eav.value_lower)
                 FROM entry_attribute_values eav
                 WHERE eav.entry_lc_dn = __base.lc_dn
                   AND eav.attr_name_lower = ?) AS {$alias}
                SQL;
            $orderTerms[] = "{$alias} IS NULL {$sortKey->direction}, {$alias} {$sortKey->direction}";
            $sortParams[] = $sortKey->attributeLower;
        }

        $projection = implode(",\n", $projections);
        $order = implode(', ', $orderTerms);
        $sql = <<<SQL
            SELECT dn, attributes FROM (
                SELECT __base.dn, __base.attributes,
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
     * Columns every list query selects; the portable sort projects lc_dn so it can correlate on the canonical DN.
     */
    protected function listColumns(): string
    {
        return 'lc_dn, dn, attributes';
    }
}
