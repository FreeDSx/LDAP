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

use PDO;

/**
 * Database-specific row locks taken within the current transaction.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoRowLockDialectInterface
{
    /**
     * Exclusively lock a row of an internal (never client-named) table until the transaction ends.
     */
    public function lockRowForWrite(
        PDO $pdo,
        string $table,
        string $keyColumn,
        string|int $key,
    ): void;

    /**
     * Share-lock a row of an internal (never client-named) table so it cannot be deleted until the transaction ends.
     */
    public function lockRowForReference(
        PDO $pdo,
        string $table,
        string $keyColumn,
        string|int $key,
    ): bool;
}
