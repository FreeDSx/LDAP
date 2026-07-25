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
use PDOStatement;

/**
 * A real PDO connection that records the statements it prepares and executes.
 */
final class RecordingPdo extends PDO
{
    /**
     * @var list<string>
     */
    public array $prepared = [];

    /**
     * @var list<string>
     */
    public array $executed = [];

    /**
     * @param array<int|string, mixed> $options
     */
    public function prepare(
        string $query,
        array $options = [],
    ): PDOStatement|false {
        $this->prepared[] = $query;

        return parent::prepare($query, $options);
    }

    public function exec(string $statement): int|false
    {
        $this->executed[] = $statement;

        return parent::exec($statement);
    }

    /**
     * @return list<string>
     */
    public function preparedMatching(string $needle): array
    {
        return array_values(array_filter(
            $this->prepared,
            static fn(string $query): bool => str_contains($query, $needle),
        ));
    }

    /**
     * @return list<string>
     */
    public function executedMatching(string $needle): array
    {
        return array_values(array_filter(
            $this->executed,
            static fn(string $statement): bool => str_contains($statement, $needle),
        ));
    }
}
