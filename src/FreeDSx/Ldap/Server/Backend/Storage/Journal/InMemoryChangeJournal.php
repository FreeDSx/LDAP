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

    public function __construct(
        private readonly ReplicaId $origin = new ReplicaId(),
        private readonly ClockInterface $clock = new SystemClock(),
    ) {}

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

    public function read(int $afterSeq = 0): iterable
    {
        foreach ($this->records as $record) {
            if ($record->seq > $afterSeq) {
                yield $record;
            }
        }
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
}
