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
 * Cross-platform transaction control shared by every PdoTransactionDialectInterface implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoTransactionDialectTrait
{
    public function beginTransaction(PDO $pdo): void
    {
        $pdo->beginTransaction();
    }

    public function commit(PDO $pdo): void
    {
        $pdo->commit();
    }

    public function rollBack(PDO $pdo): void
    {
        $pdo->rollBack();
    }
}
