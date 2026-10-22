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

namespace Tests\Support\FreeDSx\Ldap\Pdo;

use PDO;
use PDOException;
use PDOStatement;

/**
 * A real PDO connection that fails every new statement with the given failure once the database has dropped it.
 */
final class DroppablePdo extends PDO
{
    private ?PDOException $failure = null;

    public function drop(PDOException $failure): void
    {
        $this->failure = $failure;
    }

    /**
     * @param array<int|string, mixed> $options
     */
    public function prepare(
        string $query,
        array $options = [],
    ): PDOStatement|false {
        if ($this->failure !== null) {
            throw $this->failure;
        }

        return parent::prepare(
            $query,
            $options,
        );
    }

    public function exec(string $statement): int|false
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }

        return parent::exec($statement);
    }
}
