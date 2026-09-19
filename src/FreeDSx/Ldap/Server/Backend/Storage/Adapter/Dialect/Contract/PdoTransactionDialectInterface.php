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
use PDOException;

/**
 * Database-specific transaction control.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoTransactionDialectInterface
{
    /**
     * Begin a write-capable transaction.
     */
    public function beginTransaction(PDO $pdo): void;

    /**
     * Commit the current transaction.
     */
    public function commit(PDO $pdo): void;

    /**
     * Roll back the current transaction.
     */
    public function rollBack(PDO $pdo): void;

    /**
     * Whether the database guarantees the failed transaction applied nothing, making it safe to reissue.
     */
    public function isRetryableConflict(PDOException $exception): bool;
}
