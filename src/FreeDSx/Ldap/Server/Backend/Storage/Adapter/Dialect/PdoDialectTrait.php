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

use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;
use PDO;

use function strtolower;

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
        string $keyColumn,
        string|int $key,
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

    public function queryEntryId(): string
    {
        return <<<SQL
            SELECT entry_id
            FROM entries
            WHERE lc_dn = ?
        SQL;
    }

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

    public function queryHasChildren(): string
    {
        return <<<SQL
            SELECT 1
            FROM entries
            WHERE lc_parent_dn = ?
            LIMIT 1
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

    public function queryNamingContexts(): string
    {
        return <<<SQL
            SELECT dn
            FROM entries
            WHERE lc_parent_dn = ''
               OR lc_parent_dn NOT IN (SELECT lc_dn FROM entries)
        SQL;
    }

    public function queryRenameEntry(): string
    {
        return <<<SQL
            UPDATE entries
            SET dn = ?,
                lc_dn = ?,
                lc_parent_dn = ?
            WHERE lc_dn = ?
        SQL;
    }

    /**
     * One pass, since the walk reaches a deep entry only through parent links this statement rewrites.
     *
     * The stored DN is assigned first, because MySQL evaluates each assignment against the preceding ones.
     */
    public function queryRenameDescendants(): string
    {
        $carriesSuffix = $this->binaryCompare(
            'SUBSTR(dn, ' . $this->charLength('dn') . ' - ? + 1)',
            '?',
        );
        $stored = $this->replaceDnSuffix('dn');
        $canonical = $this->replaceDnSuffix('lc_dn');
        $parent = $this->replaceDnSuffix('lc_parent_dn');
        $scope = $this->scopedSubtreeIds();

        return <<<SQL
            UPDATE entries
            SET dn = CASE
                    WHEN $carriesSuffix
                    THEN $stored
                    ELSE $canonical
                END,
                lc_dn = $canonical,
                lc_parent_dn = $parent
            WHERE entry_id IN ($scope)
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
        $markers = SqlFilterUtility::markers($count);

        return <<<SQL
            DELETE FROM entries
            WHERE lc_dn IN ($markers)
        SQL;
    }

    public function querySidecarDelete(): string
    {
        return <<<SQL
            DELETE FROM entry_attribute_values
            WHERE owner_entry_id = ?
        SQL;
    }

    public function querySidecarDeleteNames(int $count): string
    {
        $markers = SqlFilterUtility::markers($count);

        return <<<SQL
            DELETE FROM entry_attribute_values
            WHERE owner_entry_id = ?
              AND attr_name_lower IN ($markers)
        SQL;
    }

    public function querySidecarInsertPrefix(): string
    {
        return 'INSERT INTO entry_attribute_values (owner_entry_id, attr_name_lower, value_lower, value_original) VALUES ';
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

    /**
     * Replaces the trailing characters of $column, the first marker naming how many and the second what replaces them.
     */
    protected function replaceDnSuffix(string $column): string
    {
        return $this->concat(
            "SUBSTR($column, 1, {$this->charLength($column)} - ?)",
            '?',
        );
    }

    /**
     * Character count, which the DN arithmetic needs: SQLite counts characters for TEXT, MySQL's LENGTH() counts bytes.
     */
    protected function charLength(string $column): string
    {
        return "LENGTH($column)";
    }

    protected function concat(
        string $left,
        string $right,
    ): string {
        return "$left || $right";
    }

    /**
     * Byte-exact comparison, which SQLite already applies to text; a collated one would let a dialect keep a spelling
     * the other adapters discard.
     */
    protected function binaryCompare(
        string $left,
        string $right,
    ): string {
        return "$left = $right";
    }

    /**
     * Entry keys under a DN, which the rename scopes on. Parameters: [lc_dn]
     */
    protected function scopedSubtreeIds(): string
    {
        return $this->subtreeWalk();
    }

    /**
     * Descends lc_parent_dn, so a rename costs its subtree rather than the whole table a DN suffix match would scan.
     */
    protected function subtreeWalk(): string
    {
        return <<<SQL
            WITH RECURSIVE subtree AS (
                SELECT entry_id, lc_dn
                FROM entries
                WHERE lc_parent_dn = ?
                UNION ALL
                SELECT e.entry_id, e.lc_dn
                FROM entries e
                INNER JOIN subtree s ON e.lc_parent_dn = s.lc_dn
            )
            SELECT entry_id FROM subtree
        SQL;
    }
}
