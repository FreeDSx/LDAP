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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\LockableTable;
use PDO;

/**
 * Cross-platform row locks shared by every PdoRowLockDialectInterface implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoRowLockDialectTrait
{
    /**
     * Default no-op: SQLite already holds the database write lock from `BEGIN IMMEDIATE`, which covers every row.
     *
     * @param list<string|int> $keys
     *
     * @return list<string|int>
     */
    public function lockRowForWrite(
        PDO $pdo,
        LockableTable $table,
        array $keys,
    ): array {
        return $keys;
    }

    public function lockRowForReference(
        PDO $pdo,
        LockableTable $table,
        string|int $key,
    ): bool {
        $keyColumn = $table->keyColumn();
        $statement = $pdo->prepare(<<<SQL
            SELECT $keyColumn
            FROM {$table->value}
            WHERE $keyColumn = ?
            SQL);
        $statement->execute([$key]);

        return $statement->fetch() !== false;
    }
}
