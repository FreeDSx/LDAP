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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use PDO;
use PDOStatement;
use Throwable;

/**
 * Prepares and executes statements, recycling them per connection so repeated queries are compiled once.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PdoStatementPool
{
    private const DEFAULT_MAX_QUERIES = 64;

    /**
     * @var array<int, array<string, list<PDOStatement>>> Per-connection pools keyed by spl_object_id, then by SQL text.
     */
    private array $pools = [];

    public function __construct(
        private readonly PdoConnectionProviderInterface $provider,
        private readonly int $maxQueries = self::DEFAULT_MAX_QUERIES,
    ) {
        // Make sure we clean-up cached statements when the provider closes the connection.
        $provider->onConnectionReleased($this->forget(...));
    }

    /**
     * Leases a statement for the query, executes it, and returns it to the pool once the result is released.
     *
     * @param list<string|int|null> $params
     *
     * @throws StorageIoException when the statement cannot be prepared
     */
    public function execute(
        string $query,
        array $params = [],
    ): PooledStatement {
        $pdo = $this->provider->get();
        $key = spl_object_id($pdo);
        $statement = $this->lease(
            $pdo,
            $key,
            $query,
        );

        $this->bind($statement, $params);
        $statement->execute();

        return new PooledStatement(
            $statement,
            function (PDOStatement $released) use ($key, $query): void {
                $this->release(
                    $key,
                    $query,
                    $released,
                );
            },
        );
    }

    /**
     * Drops every pooled statement, for when the underlying connections are replaced.
     */
    public function reset(): void
    {
        $this->pools = [];
    }

    private function forget(PDO $pdo): void
    {
        unset($this->pools[spl_object_id($pdo)]);
    }

    /**
     * @throws StorageIoException
     */
    private function lease(
        PDO $pdo,
        int $key,
        string $query,
    ): PDOStatement {
        $pools = &$this->pools[$key];
        $pools ??= [];

        if (isset($pools[$query])) {
            // Re-inserting the key moves it last so eviction sheds the least recently used query.
            $statements = $pools[$query];
            unset($pools[$query]);
            $pools[$query] = $statements;

            $pooled = array_pop($pools[$query]);
            if ($pooled !== null) {
                return $pooled;
            }
        } elseif (count($pools) >= $this->maxQueries) {
            array_shift($pools);
        }

        $statement = $pdo->prepare($query);
        if ($statement === false) {
            throw new StorageIoException('Failed to prepare SQL statement.');
        }

        $pools[$query] ??= [];

        return $statement;
    }

    /**
     * Binds positionally, typing each value so native prepares accept non-string parameters such as LIMIT.
     *
     * @param list<string|int|null> $params
     */
    private function bind(
        PDOStatement $statement,
        array $params,
    ): void {
        $position = 1;

        foreach ($params as $param) {
            $statement->bindValue(
                $position++,
                $param,
                match (true) {
                    $param === null => PDO::PARAM_NULL,
                    is_int($param) => PDO::PARAM_INT,
                    default => PDO::PARAM_STR,
                },
            );
        }
    }

    private function release(
        int $key,
        string $query,
        PDOStatement $statement,
    ): void {
        try {
            $statement->closeCursor();
        } catch (Throwable) {
            return;
        }

        if (!isset($this->pools[$key][$query])) {
            return;
        }

        $this->pools[$key][$query][] = $statement;
    }
}
