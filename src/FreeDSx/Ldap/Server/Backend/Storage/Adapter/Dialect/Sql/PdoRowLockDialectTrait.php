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

use PDO;

/**
 * Cross-platform row locks shared by every PdoRowLockDialectInterface implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoRowLockDialectTrait
{
    /**
     * Default no-op: SQLite already holds the write lock from `BEGIN IMMEDIATE`, so no per-row lock is needed.
     */
    public function lockRowForWrite(
        PDO $pdo,
        string $table,
        string $keyColumn,
        string|int $key,
    ): void {}

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
            SQL);
        $statement->execute([$key]);

        return $statement->fetch() !== false;
    }
}
