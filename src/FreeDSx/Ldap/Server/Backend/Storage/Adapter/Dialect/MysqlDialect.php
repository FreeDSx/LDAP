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
 * MySQL/MariaDB SQL for PdoStorage; requires MySQL 8.0+ or MariaDB 10.6+.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MysqlDialect implements PdoDialectInterface
{
    use PdoDialectTrait;
    use PdoJournalDialectTrait;
    use PdoSchemaTrait;

    /**
     * Deadlock found when trying to get lock. The transaction has already been rolled back.
     */
    private const ERROR_DEADLOCK = 1213;

    /**
     * Lock wait timeout exceeded.
     */
    private const ERROR_LOCK_WAIT_TIMEOUT = 1205;

    /**
     * Duplicate entry for key.
     */
    private const ERROR_DUPLICATE_ENTRY = 1062;

    /**
     * Data too long for a column.
     */
    private const ERROR_DATA_TOO_LONG = 1406;

    /**
     * InnoDB resolves lock conflicts by failing one transaction, which is then safe to reissue unchanged.
     */
    public function isRetryableConflict(PDOException $exception): bool
    {
        $driverCode = $exception->errorInfo[1] ?? null;

        return $driverCode === self::ERROR_DEADLOCK
            || $driverCode === self::ERROR_LOCK_WAIT_TIMEOUT;
    }

    public function isDuplicateEntry(PDOException $exception): bool
    {
        return ($exception->errorInfo[1] ?? null) === self::ERROR_DUPLICATE_ENTRY;
    }

    public function isValueTooLong(PDOException $exception): bool
    {
        return ($exception->errorInfo[1] ?? null) === self::ERROR_DATA_TOO_LONG;
    }

    public function lockRowForWrite(
        PDO $pdo,
        string $table,
        string $keyColumn,
        string|int $key,
    ): void {
        $statement = $pdo->prepare(<<<SQL
            SELECT $keyColumn
            FROM $table
            WHERE $keyColumn = ?
            FOR UPDATE
            SQL);
        $statement->execute([$key]);
    }

    public function lockRowForReference(
        PDO $pdo,
        string $table,
        string $keyColumn,
        string|int $key,
    ): bool {
        $statement = $pdo->prepare(<<<SQL
            SELECT $keyColumn
            FROM $table
            WHERE $keyColumn = ?
            FOR SHARE
            SQL);
        $statement->execute([$key]);

        return $statement->fetch() !== false;
    }

    /**
     * @todo Replace VALUES() with row alias syntax once MariaDB supports it.
     */
    public function queryUpsert(): string
    {
        return <<<SQL
            INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                dn = VALUES(dn),
                lc_parent_dn = VALUES(lc_parent_dn),
                attributes = VALUES(attributes)
        SQL;
    }

    /**
     * What the DN columns hold, which is InnoDB's own ceiling for the unique key over one of them.
     */
    public function maxDnLength(): int
    {
        return 3072;
    }

    protected function charLength(string $column): string
    {
        return "CHAR_LENGTH($column)";
    }

    /**
     * The DN columns are binary, where CHAR_LENGTH and SUBSTR would count bytes rather than the characters PHP passes.
     */
    protected function textOf(string $column): string
    {
        return "CONVERT($column USING utf8mb4)";
    }

    protected function concat(
        string $left,
        string $right,
    ): string {
        return "CONCAT($left, $right)";
    }

    /**
     * The entry table's collation is case-insensitive, so the comparison is taken to bytes to match every other adapter.
     */
    protected function binaryCompare(
        string $left,
        string $right,
    ): string {
        return "CAST($left AS BINARY) = CAST($right AS BINARY)";
    }

    /**
     * Wrapped in a derived table, which MySQL materializes.
     *
     * A subquery is otherwise refused for reading the table the statement is updating.
     */
    protected function scopedSubtreeIds(): string
    {
        $walk = $this->subtreeWalk();

        return <<<SQL
            SELECT scoped.entry_id FROM ($walk) AS scoped
        SQL;
    }

    protected function schemaName(): string
    {
        return 'mysql';
    }
}
