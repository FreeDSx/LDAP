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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqliteFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use PDO;

/**
 * SQLite-specific SQL for PdoStorage.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SqliteDialect implements PdoDialectInterface
{
    use PdoDialectTrait;
    use PdoJournalDialectTrait;
    use PdoSchemaTrait;

    public function createFilterTranslator(?SubstringIndexInterface $substringIndex): FilterTranslatorInterface
    {
        return new SqliteFilterTranslator($substringIndex);
    }

    /**
     * `BEGIN IMMEDIATE` acquires the reserved lock up front so concurrent writers wait (honoring `busy_timeout`)
     * instead of racing, which returns SQLITE_BUSY immediately to avoid deadlock.
     */
    public function beginTransaction(PDO $pdo): void
    {
        $pdo->exec('BEGIN IMMEDIATE');
    }

    public function commit(PDO $pdo): void
    {
        $pdo->exec('COMMIT');
    }

    public function rollBack(PDO $pdo): void
    {
        $pdo->exec('ROLLBACK');
    }

    /**
     * Upserts an entry in place via ON CONFLICT rather than INSERT OR REPLACE, because REPLACE deletes the row first and
     * fires ON DELETE CASCADE, which would wipe child rows such as the replica password-policy state.
     */
    public function queryUpsert(): string
    {
        return <<<SQL
            INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(lc_dn) DO UPDATE SET
                dn = excluded.dn,
                lc_parent_dn = excluded.lc_parent_dn,
                attributes = excluded.attributes
        SQL;
    }

    public function maxDnLength(): ?int
    {
        return null;
    }

    public function sortedQuery(
        string $baseSql,
        array $baseParams,
        array $sortKeys,
    ): SortedQuery {
        $terms = [];
        $sortParams = [];

        // RFC 2891 §2.2: NULL is the largest value, so missing entries sort last (ASC) or first (DESC). Native
        // NULLS ordering evaluates the correlated subquery once, so the base query needs no wrapping.
        foreach ($sortKeys as $sortKey) {
            $nulls = $sortKey->direction === 'ASC'
                ? 'NULLS LAST'
                : 'NULLS FIRST';
            $terms[] = <<<SQL
                (SELECT MIN(eav.value_lower)
                 FROM entry_attribute_values eav
                 WHERE eav.entry_lc_dn = lc_dn
                   AND eav.attr_name_lower = ?) {$sortKey->direction} {$nulls}
                SQL;
            $sortParams[] = $sortKey->attributeLower;
        }

        return new SortedQuery(
            $baseSql . ' ORDER BY ' . implode(', ', $terms),
            array_merge(
                $baseParams,
                $sortParams,
            ),
        );
    }

    /**
     * Sorting reads lc_dn straight off the row source rather than a derived table, so it need not be selected.
     */
    protected function listColumns(): string
    {
        return 'dn, attributes';
    }

    protected function schemaName(): string
    {
        return 'sqlite';
    }
}
