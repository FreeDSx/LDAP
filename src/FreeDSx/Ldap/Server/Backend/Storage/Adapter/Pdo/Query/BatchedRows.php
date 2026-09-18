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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PooledStatement;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use Generator;
use IteratorAggregate;

use function microtime;

/**
 * One statement's rows, bounded by the deadline and the cap, counting what it read as it goes.
 *
 * @implements IteratorAggregate<int, mixed>
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class BatchedRows implements IteratorAggregate
{
    private int $read = 0;

    private bool $hasMore = false;

    /**
     * @param ?int $cap Rows to hand over before stopping, leaving the rest to prove the result continues.
     */
    public function __construct(
        private readonly PooledStatement $statement,
        private readonly ?float $deadline = null,
        private readonly ?int $cap = null,
    ) {}

    /**
     * @return Generator<int, mixed>
     * @throws TimeLimitExceededException
     */
    public function getIterator(): Generator
    {
        while (($row = $this->statement->fetch()) !== false) {
            if ($this->deadline !== null && microtime(true) >= $this->deadline) {
                throw new TimeLimitExceededException();
            }

            // Read but not handed over: its only job is to prove the result did not end here.
            if ($this->cap !== null && $this->read >= $this->cap) {
                $this->hasMore = true;

                break;
            }

            $this->read++;

            yield $row;
        }
    }

    public function read(): int
    {
        return $this->read;
    }

    public function hasMore(): bool
    {
        return $this->hasMore;
    }
}
