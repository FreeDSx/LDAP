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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use Closure;
use PDOStatement;
use Throwable;

/**
 * RAII wrapper around a PDOStatement leased from a per-query pool; returns it on destruction.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PooledStatement
{
    private ?Closure $release;

    public function __construct(
        private readonly PDOStatement $statement,
        Closure $release,
    ) {
        $this->release = $release;
    }

    public function fetch(): mixed
    {
        return $this->statement->fetch();
    }

    public function __destruct()
    {
        if ($this->release === null) {
            return;
        }

        $release = $this->release;
        $this->release = null;

        try {
            $release($this->statement);
        } catch (Throwable) {
            // Drop the statement rather than recycling a poisoned one into the pool.
        }
    }
}
