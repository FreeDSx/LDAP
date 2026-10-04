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

namespace FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared;

use FreeDSx\Ldap\Exception\RuntimeException;
use Swoole\Atomic\Long;

use function sprintf;

/**
 * Connection slots counted in shared memory, against the server's connection limit.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ConnectionSlots
{
    private readonly Long $total;

    /**
     * Connection counts held per-worker.
     *
     * @var array<int, Long>
     */
    private readonly array $byWorker;

    private int $workerId = 0;

    /**
     * Must be built before a pool forks, so every worker shares the same counters.
     */
    public function __construct(int $workers = 1)
    {
        $this->total = new Long();

        $byWorker = [];
        for ($workerId = 0; $workerId < $workers; $workerId++) {
            $byWorker[$workerId] = new Long();
        }
        $this->byWorker = $byWorker;
    }

    /**
     * Takes a slot unless the limit is already reached; a limit of zero or less is no limit.
     *
     * Adds first and backs out when over.
     */
    public function tryAcquire(int $maxConnections): bool
    {
        $held = $this->heldByThisWorker();
        $held->add(1);
        $total = $this->total->add(1);

        if ($maxConnections <= 0 || $total <= $maxConnections) {
            return true;
        }

        $this->total->sub(1);
        $held->sub(1);

        return false;
    }

    public function release(): void
    {
        $this->total->sub(1);
        $this->heldByThisWorker()->sub(1);
    }

    public function claimWorker(int $workerId): void
    {
        $this->workerId = $workerId;
        $held = $this->heldByThisWorker();

        $this->total->sub($held->get());
        $held->set(0);
    }

    private function heldByThisWorker(): Long
    {
        return $this->byWorker[$this->workerId] ?? throw new RuntimeException(sprintf(
            'No connection slots were allocated for worker %d.',
            $this->workerId,
        ));
    }
}
