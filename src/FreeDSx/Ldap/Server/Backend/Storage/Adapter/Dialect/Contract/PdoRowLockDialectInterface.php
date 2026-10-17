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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\LockableTable;
use PDO;

/**
 * Database-specific row locks taken within the current transaction.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoRowLockDialectInterface
{
    /**
     * Exclusively lock the rows by key until the transaction ends, answering the keys of those it holds.
     *
     * @param list<string|int> $keys
     *
     * @return list<string|int>
     */
    public function lockRowForWrite(
        PDO $pdo,
        LockableTable $table,
        array $keys,
    ): array;

    /**
     * Share-lock a row so it cannot be deleted until the transaction ends.
     */
    public function lockRowForReference(
        PDO $pdo,
        LockableTable $table,
        string|int $key,
    ): bool;
}
