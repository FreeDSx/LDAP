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
use PDOException;

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

    /**
     * The database file is locked by another writer.
     */
    private const ERROR_BUSY = 5;

    /**
     * A table in the database is locked, which the busy handler is never invoked for.
     */
    private const ERROR_LOCKED = 6;

    /**
     * A constraint was violated. For an entry insert that's the unique key on lc_dn.
     */
    private const ERROR_CONSTRAINT = 19;

    /**
     * `busy_timeout` absorbs most contention by waiting, but it still gives up once the timeout is exhausted.
     */
    public function isRetryableConflict(PDOException $exception): bool
    {
        $driverCode = $exception->errorInfo[1] ?? null;

        return $driverCode === self::ERROR_BUSY
            || $driverCode === self::ERROR_LOCKED;
    }

    public function isDuplicateEntry(PDOException $exception): bool
    {
        return ($exception->errorInfo[1] ?? null) === self::ERROR_CONSTRAINT;
    }

    /**
     * SQLite declares no length on its columns.
     */
    public function isValueTooLong(PDOException $exception): bool
    {
        return false;
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
            $value = $sortKey->numeric
                ? 'CAST(eav.value_lower AS INTEGER)'
                : 'eav.value_lower';
            $terms[] = <<<SQL
                (SELECT MIN({$value})
                 FROM entry_attribute_values eav
                 WHERE eav.owner_entry_id = entry_id
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
     * Sorting reads entry_id straight off the row source, but a resumable list reads it off the row, so it is selected.
     */
    protected function listColumns(): string
    {
        return 'entry_id, dn, attributes';
    }

    protected function schemaName(): string
    {
        return 'sqlite';
    }
}
