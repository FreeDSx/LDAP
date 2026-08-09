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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\StorageLockInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Serializer\ChangeRecordRowMapper;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Serializer\JsonlRowSerializer;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Serializer\RowSerializerInterface;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Clock\SystemClock;
use Generator;

use function array_filter;
use function array_slice;
use function array_values;
use function count;
use function dirname;
use function explode;
use function fclose;
use function fflush;
use function file_get_contents;
use function file_put_contents;
use function fopen;
use function fwrite;
use function implode;
use function is_file;
use function is_numeric;
use function rename;
use function tempnam;
use function trim;
use function unlink;

/**
 * Change journal persisting records to an append-only line-per-record sidecar under the storage's file lock.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FileChangeJournal implements ChangeJournalInterface
{
    public function __construct(
        private StorageLockInterface $lock,
        private string $journalPath,
        private string $seqPath,
        private ReplicaId $origin = new ReplicaId(),
        private ClockInterface $clock = new SystemClock(),
        private RowSerializerInterface $serializer = new JsonlRowSerializer(),
        private ChangeRecordRowMapper $mapper = new ChangeRecordRowMapper(),
    ) {}

    public function append(PendingChange $change): ChangeRecord
    {
        $createdAt = $this->clock->now();
        $seq = 0;

        // Bump the counter before writing the line: a failed append leaves a seq gap, never a reused seq.
        $this->lock->withExclusive(function () use ($change, $createdAt, &$seq): void {
            $seq = $this->readSeq() + 1;
            $this->writeSeq($seq);
            $this->appendLine($this->serializer->encode($this->mapper->toRow(new ChangeRecord(
                seq: $seq,
                origin: $this->origin,
                createdAt: $createdAt,
                change: $change,
            ))));
        });

        return new ChangeRecord(
            seq: $seq,
            origin: $this->origin,
            createdAt: $createdAt,
            change: $change,
        );
    }

    public function read(int $afterSeq = 0): iterable
    {
        $lines = [];

        $this->lock->withExclusive(function () use (&$lines): void {
            $lines = $this->readLines();
        });

        return $this->streamRecords(
            $lines,
            $afterSeq,
        );
    }

    public function latestSeq(): int
    {
        $seq = 0;

        $this->lock->withExclusive(function () use (&$seq): void {
            $seq = $this->readSeq();
        });

        return $seq;
    }

    public function retainsSince(int $afterSeq): bool
    {
        $minSeq = null;
        $latest = 0;

        $this->lock->withExclusive(function () use (&$minSeq, &$latest): void {
            $minSeq = $this->readMinSeq();
            $latest = $this->readSeq();
        });

        // Empty journal: only a consumer already at the high-water mark is retained.
        if ($minSeq === null) {
            return $afterSeq >= $latest;
        }

        return $afterSeq + 1 >= $minSeq;
    }

    public function prune(RetentionPolicy $policy): int
    {
        $removed = 0;

        $this->lock->withExclusive(function () use ($policy, &$removed): void {
            $lines = $this->readLines();
            $kept = $this->applyPolicy(
                $lines,
                $policy,
            );

            if (count($kept) !== count($lines)) {
                $this->rewriteLines($kept);
            }

            $removed = count($lines) - count($kept);
        });

        return $removed;
    }

    public function origin(): ReplicaId
    {
        return $this->origin;
    }

    public function sharesAcrossProcesses(): bool
    {
        return true;
    }

    private function decodeLine(string $line): ?ChangeRecord
    {
        $row = $this->serializer->decode($line);

        return $row === null
            ? null
            : $this->mapper->fromRow($row);
    }

    /**
     * @param list<string> $lines
     *
     * @return Generator<ChangeRecord>
     */
    private function streamRecords(
        array $lines,
        int $afterSeq,
    ): Generator {
        foreach ($lines as $line) {
            $record = $this->decodeLine($line);

            if ($record !== null && $record->seq > $afterSeq) {
                yield $record;
            }
        }
    }

    /**
     * @param list<string> $lines
     *
     * @return list<string>
     */
    private function applyPolicy(
        array $lines,
        RetentionPolicy $policy,
    ): array {
        if ($policy->maxRecords !== null && count($lines) > $policy->maxRecords) {
            $lines = array_slice(
                $lines,
                count($lines) - $policy->maxRecords,
            );
        }

        if ($policy->maxAgeSeconds !== null) {
            $oldest = $this->clock->now()->getTimestamp() - $policy->maxAgeSeconds;
            $lines = array_values(array_filter(
                $lines,
                function (string $line) use ($oldest): bool {
                    $record = $this->decodeLine($line);

                    // A torn line has no timestamp, so it is treated as oldest and reclaimed.
                    return $record !== null && $record->createdAt->getTimestamp() >= $oldest;
                },
            ));
        }

        return $lines;
    }

    private function readSeq(): int
    {
        if (!is_file($this->seqPath)) {
            return 0;
        }

        $raw = file_get_contents($this->seqPath);

        if ($raw === false) {
            throw new StorageIoException('Unable to read the change journal sequence counter.');
        }

        $raw = trim($raw);

        return is_numeric($raw)
            ? (int) $raw
            : 0;
    }

    private function writeSeq(int $seq): void
    {
        $this->atomicWrite(
            $this->seqPath,
            (string) $seq,
        );
    }

    private function readMinSeq(): ?int
    {
        foreach ($this->readLines() as $line) {
            $record = $this->decodeLine($line);

            if ($record !== null) {
                return $record->seq;
            }
        }

        return null;
    }

    private function appendLine(string $line): void
    {
        $handle = fopen($this->journalPath, 'a');

        if ($handle === false) {
            throw new StorageIoException('Unable to open the change journal for appending.');
        }

        try {
            if (fwrite($handle, $line . "\n") === false) {
                throw new StorageIoException('Unable to append to the change journal.');
            }

            fflush($handle);
        } finally {
            fclose($handle);
        }
    }

    /**
     * @return list<string>
     */
    private function readLines(): array
    {
        if (!is_file($this->journalPath)) {
            return [];
        }

        $raw = file_get_contents($this->journalPath);

        if ($raw === false) {
            throw new StorageIoException('Unable to read the change journal.');
        }

        $lines = [];
        foreach (explode("\n", $raw) as $line) {
            if ($line !== '') {
                $lines[] = $line;
            }
        }

        return $lines;
    }

    /**
     * @param list<string> $lines
     */
    private function rewriteLines(array $lines): void
    {
        $this->atomicWrite(
            $this->journalPath,
            $lines === [] ? '' : implode("\n", $lines) . "\n",
        );
    }

    private function atomicWrite(
        string $path,
        string $contents,
    ): void {
        $tmpPath = tempnam(
            dirname($path),
            'ldap-journal-',
        );

        if ($tmpPath === false) {
            throw new StorageIoException('Unable to stage a change journal update.');
        }

        if (file_put_contents($tmpPath, $contents) === false) {
            @unlink($tmpPath);

            throw new StorageIoException('Unable to stage a change journal update.');
        }

        if (!rename($tmpPath, $path)) {
            @unlink($tmpPath);

            throw new StorageIoException('Unable to publish a change journal update.');
        }
    }
}
