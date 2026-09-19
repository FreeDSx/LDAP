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
 * Cross-platform entry write SQL shared by every PdoEntryWriteDialectInterface implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoEntryWriteDialectTrait
{
    public function queryInsert(): string
    {
        return <<<SQL
            INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes)
            VALUES (?, ?, ?, ?)
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
        $storedDn = $this->textOf('dn');
        $carriesSuffix = $this->binaryCompare(
            "SUBSTR($storedDn, " . $this->charLength($storedDn) . ' - ? + 1)',
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

    /**
     * Replaces the trailing characters of $column, the first marker naming how many and the second what replaces them.
     */
    protected function replaceDnSuffix(string $column): string
    {
        $text = $this->textOf($column);

        return $this->concat(
            "SUBSTR($text, 1, {$this->charLength($text)} - ?)",
            '?',
        );
    }

    /**
     * The column read as text, so the DN arithmetic counts characters wherever a dialect stores the DN as bytes.
     */
    protected function textOf(string $column): string
    {
        return $column;
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
