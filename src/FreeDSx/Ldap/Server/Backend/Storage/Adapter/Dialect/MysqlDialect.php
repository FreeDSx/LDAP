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
     * InnoDB resolves lock conflicts by failing one transaction, which is then safe to reissue unchanged.
     */
    public function isRetryableConflict(PDOException $exception): bool
    {
        $driverCode = $exception->errorInfo[1] ?? null;

        return $driverCode === self::ERROR_DEADLOCK
            || $driverCode === self::ERROR_LOCK_WAIT_TIMEOUT;
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

    public function maxDnLength(): int
    {
        return 768;
    }

    protected function schemaName(): string
    {
        return 'mysql';
    }
}
