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

namespace FreeDSx\Ldap\Protocol\Queue\Budget;

use Closure;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Resources\SystemResources;

use function intdiv;
use function microtime;

/**
 * The bytes of the requests every connection of a process holds at once, in total and for each identity's share.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class RequestBudget
{
    /**
     * The limit when the process has no memory limit to take half of, in bytes (512 MiB).
     */
    private const LIMIT_WITHOUT_MEMORY_LIMIT = 536_870_912;

    private const ROOM_POLL_SECONDS = 0.05;

    private int $held = 0;

    /**
     * The bytes counted for each share that holds any, by its key.
     *
     * @var array<string, int>
     */
    private array $heldByShare = [];

    public function __construct(
        private readonly SleeperInterface $sleeper = new BlockingSleeper(),
        private readonly SystemResources $resources = new SystemResources(),
    ) {}

    /**
     * The limit in bytes for a configured size, or half of the memory limit when none is set.
     */
    public function limitFor(?int $configured): int
    {
        if ($configured !== null) {
            return $configured;
        }
        $bytes = $this->resources->memoryLimit()->getBytes();

        return $bytes === null
            ? self::LIMIT_WITHOUT_MEMORY_LIMIT
            : intdiv(
                $bytes,
                2,
            );
    }

    /**
     * Counts the bytes when they fit within the limit in bytes and the share, reclaiming memory once before giving up.
     */
    public function reserve(
        int $bytes,
        int $limit,
        BudgetShare $share,
    ): ?BudgetReservation {
        if (!$this->take($bytes, $limit, $share) && !$this->takeOnceReclaimed($bytes, $limit, $share)) {
            return null;
        }

        return new BudgetReservation(
            $this,
            $bytes,
            $share->key,
        );
    }

    /**
     * Counts the bytes under the share whether or not they fit.
     */
    public function reserveAnyway(
        int $bytes,
        BudgetShare $share,
    ): BudgetReservation {
        $this->count(
            $bytes,
            $share->key,
        );

        return new BudgetReservation(
            $this,
            $bytes,
            $share->key,
        );
    }

    /**
     * Waits until there is room, or returns false once the deadline in microtime passes first.
     *
     * @param Closure(): bool $hasRoom
     */
    public function waitForRoom(
        Closure $hasRoom,
        ?float $deadline,
    ): bool {
        $isReclaimed = false;
        while (!$hasRoom()) {
            if ($deadline !== null && microtime(true) >= $deadline) {
                return false;
            }
            $this->pause($isReclaimed);
            $isReclaimed = true;
        }

        return true;
    }

    /**
     * The bytes counted now.
     */
    public function held(): int
    {
        return $this->held;
    }

    /**
     * The bytes counted now under the share.
     */
    public function heldBy(BudgetShare $share): int
    {
        return $this->heldByShare[$share->key] ?? 0;
    }

    /**
     * Whether adding the bytes keeps the count within the limit and the share, where a limit of 0 means no limit.
     */
    public function fits(
        int $bytes,
        int $limit,
        BudgetShare $share,
    ): bool {
        return $limit <= 0
            || ($this->held + $bytes <= $limit && $this->heldBy($share) + $bytes <= $share->limit);
    }

    public function release(
        int $bytes,
        string $shareKey,
    ): void {
        $this->held -= $bytes;
        $this->heldByShare[$shareKey] = ($this->heldByShare[$shareKey] ?? 0) - $bytes;

        // Dropping a share that holds nothing keeps the count from growing with every identity ever seen.
        if ($this->heldByShare[$shareKey] === 0) {
            unset($this->heldByShare[$shareKey]);
        }
    }

    private function count(
        int $bytes,
        string $shareKey,
    ): void {
        $this->held += $bytes;
        $this->heldByShare[$shareKey] = ($this->heldByShare[$shareKey] ?? 0) + $bytes;
    }

    /**
     * Adds to the count when the result fits within the limit and the share, where a limit of 0 means no limit.
     */
    private function take(
        int $bytes,
        int $limit,
        BudgetShare $share,
    ): bool {
        if (!$this->fits($bytes, $limit, $share)) {
            return false;
        }
        $this->count(
            $bytes,
            $share->key,
        );

        return true;
    }

    /**
     * Memory is reclaimed only for bytes that could fit within the whole limit and the share.
     */
    private function takeOnceReclaimed(
        int $bytes,
        int $limit,
        BudgetShare $share,
    ): bool {
        if ($bytes > $limit || $bytes > $share->limit) {
            return false;
        }
        $this->reclaim();

        return $this->take(
            $bytes,
            $limit,
            $share,
        );
    }

    /**
     * Reclaims memory the first time a wait finds no room, and sleeps every time after.
     */
    private function pause(bool $isReclaimed): void
    {
        if (!$isReclaimed) {
            $this->reclaim();

            return;
        }
        $this->sleeper->sleep(self::ROOM_POLL_SECONDS);
    }

    /**
     * Requests that only the cycle collector frees would otherwise stay counted.
     */
    private function reclaim(): void
    {
        $this->resources->reclaimMemory();
    }
}
