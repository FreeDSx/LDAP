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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Clock\SystemClock;
use FreeDSx\Ldap\Server\Utility\Uuid;

/**
 * Array-backed change journal. Used for in-process runners.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class InMemoryChangeJournal implements ChangeJournalInterface
{
    /**
     * @var list<ChangeRecord>
     */
    private array $records = [];

    private int $seq = 0;

    private readonly string $generation;

    public function __construct(
        private readonly ReplicaId $origin = new ReplicaId(),
        private readonly ClockInterface $clock = new SystemClock(),
    ) {
        $this->generation = Uuid::v4();
    }

    public function append(PendingChange $change): ChangeRecord
    {
        $record = new ChangeRecord(
            seq: ++$this->seq,
            origin: $this->origin,
            createdAt: $this->clock->now(),
            change: $change,
        );
        $this->records[] = $record;

        return $record;
    }

    public function appendAll(array $changes): array
    {
        return array_map(
            $this->append(...),
            $changes,
        );
    }

    /**
     * @return list<ChangeRecord>
     */
    public function read(
        int $afterSeq = 0,
        ?int $throughSeq = null,
        int $limit = self::DEFAULT_READ_LIMIT,
    ): array {
        $from = $this->firstAfter($afterSeq);
        $to = $throughSeq === null
            ? count($this->records)
            : $this->firstAfter($throughSeq);

        return array_slice(
            $this->records,
            $from,
            max(
                0,
                min(
                    $limit,
                    $to - $from,
                ),
            ),
        );
    }

    public function latestSeq(): int
    {
        return $this->seq;
    }

    public function retainsSince(int $afterSeq): bool
    {
        // Prune drops an oldest-first prefix, so the first retained record is the window floor. An
        // empty journal only serves a consumer already at the high-water mark.
        if ($this->records === []) {
            return $afterSeq >= $this->seq;
        }

        return $afterSeq + 1 >= $this->records[0]->seq;
    }

    public function origin(): ReplicaId
    {
        return $this->origin;
    }

    public function generation(): string
    {
        return $this->generation;
    }

    public function sharesAcrossProcesses(): bool
    {
        return false;
    }

    public function prune(RetentionPolicy $policy): int
    {
        $before = count($this->records);
        $records = $this->records;

        if ($policy->maxRecords !== null && count($records) > $policy->maxRecords) {
            $records = array_slice(
                $records,
                count($records) - $policy->maxRecords,
            );
        }

        if ($policy->maxAgeSeconds !== null) {
            $oldest = $this->clock->now()->getTimestamp() - $policy->maxAgeSeconds;
            $records = array_filter(
                $records,
                static fn(ChangeRecord $record): bool => $record->createdAt->getTimestamp() >= $oldest,
            );
        }

        $this->records = array_values($records);

        return $before - count($this->records);
    }

    /**
     * The index of the first record past the seq, found by halving since records are kept in seq order.
     */
    private function firstAfter(int $seq): int
    {
        $low = 0;
        $high = count($this->records);

        while ($low < $high) {
            $mid = intdiv(
                $low + $high,
                2,
            );

            if ($this->records[$mid]->seq <= $seq) {
                $low = $mid + 1;

                continue;
            }

            $high = $mid;
        }

        return $low;
    }
}
