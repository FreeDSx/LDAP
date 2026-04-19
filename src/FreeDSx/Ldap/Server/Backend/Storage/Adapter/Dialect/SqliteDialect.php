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
 * SQLite-specific SQL for PdoStorage.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SqliteDialect implements PdoDialectInterface
{
    use PdoDialectTrait;

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

    public function ddlCreateTable(): string
    {
        return <<<SQL
            CREATE TABLE IF NOT EXISTS entries (
                lc_dn         TEXT NOT NULL PRIMARY KEY,
                dn            TEXT NOT NULL,
                lc_parent_dn  TEXT NOT NULL DEFAULT '',
                attributes    TEXT NOT NULL DEFAULT '{}'
            )
        SQL;
    }

    public function ddlCreateIndex(): string
    {
        return <<<SQL
            CREATE INDEX IF NOT EXISTS idx_lc_parent_dn ON entries (lc_parent_dn)
        SQL;
    }

    public function queryUpsert(): string
    {
        return <<<SQL
            INSERT OR REPLACE
            INTO entries (lc_dn, dn, lc_parent_dn, attributes)
            VALUES (?, ?, ?, ?)
        SQL;
    }

    public function maxDnLength(): ?int
    {
        return null;
    }
}
