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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoJournalDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PooledStatement;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Clock\EpochMicroseconds;
use FreeDSx\Ldap\Server\Clock\SystemClock;
use Generator;

/**
 * Change journal persisting records to the same database and transaction as its PdoStorage.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PdoChangeJournal implements ChangeJournalInterface
{
    public function __construct(
        private PdoTransactor $transactor,
        private PdoJournalDialectInterface $dialect,
        private PdoStatementPool $statements,
        private ReplicaId $origin = new ReplicaId('local'),
        private ClockInterface $clock = new SystemClock(),
    ) {}

    public function append(PendingChange $change): ChangeRecord
    {
        $createdAt = $this->clock->now();
        $normDn = $change->dn->normalize();
        $seq = 0;

        // Joins the write transaction that a journaled change already runs in, rather than nesting a savepoint in it.
        $this->transactor->joinAtomic(function () use ($change, $normDn, $createdAt, &$seq): void {
            $this->statements->execute($this->dialect->queryJournalSeqBump());
            $seq = $this->latestSeq();

            $this->statements->execute($this->dialect->queryJournalInsert(), [
                $seq,
                (string) $this->origin,
                EpochMicroseconds::fromDateTime($createdAt),
                $change->changeType->value,
                $change->dn->toString(),
                $normDn->toString(),
                $normDn->getParent()?->toString() ?? '',
                $change->entryUuid,
                $change->authzId->toString(),
                $change->previousDn?->toString(),
                $this->encodePreImage($change->preImage),
            ]);
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
        return $this->streamRecords($this->statements->execute(
            $this->dialect->queryJournalReadSince(),
            [$afterSeq],
        ));
    }

    public function latestSeq(): int
    {
        return $this->statements
            ->execute($this->dialect->queryJournalSeqRead())
            ->fetchIntColumn() ?? 0;
    }

    public function retainsSince(int $afterSeq): bool
    {
        $minSeq = $this->statements
            ->execute($this->dialect->queryJournalMinSeq())
            ->fetchIntColumn();

        // Empty journal: only a consumer already at the high-water mark is retained (mirrors InMemoryChangeJournal).
        if ($minSeq === null) {
            return $afterSeq >= $this->latestSeq();
        }

        return $afterSeq + 1 >= $minSeq;
    }

    public function prune(RetentionPolicy $policy): int
    {
        $removed = 0;

        $this->transactor->atomic(function () use ($policy, &$removed): void {
            if ($policy->maxRecords !== null) {
                $removed += $this->pruneToRecordCap($policy->maxRecords);
            }

            if ($policy->maxAgeSeconds !== null) {
                $removed += $this->pruneToAgeWindow($policy->maxAgeSeconds);
            }
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

    private function pruneToRecordCap(int $maxRecords): int
    {
        $keepFrom = $this->statements
            ->execute(
                $this->dialect->queryJournalKeepFloor(),
                [$maxRecords - 1],
            )
            ->fetchIntColumn();

        if ($keepFrom === null) {
            return 0;
        }

        return $this->statements
            ->execute(
                $this->dialect->queryJournalDeleteBelow(),
                [$keepFrom],
            )
            ->rowCount();
    }

    private function pruneToAgeWindow(int $maxAgeSeconds): int
    {
        $cutoff = EpochMicroseconds::fromSeconds($this->clock->now()->getTimestamp() - $maxAgeSeconds);

        return $this->statements
            ->execute(
                $this->dialect->queryJournalDeleteByAge(),
                [$cutoff],
            )
            ->rowCount();
    }

    /**
     * @param array<array-key, mixed> $row
     */
    private function toRecord(array $row): ChangeRecord
    {
        $dn = new Dn($this->stringColumn($row, 'dn'));
        $previousDn = is_string($row['previous_dn'] ?? null)
            ? new Dn($this->stringColumn($row, 'previous_dn'))
            : null;

        return new ChangeRecord(
            seq: $this->intColumn($row, 'seq'),
            origin: new ReplicaId($this->stringColumn($row, 'origin')),
            createdAt: EpochMicroseconds::toDateTime($this->intColumn($row, 'created_at')),
            change: new PendingChange(
                changeType: ChangeType::from($this->stringColumn($row, 'change_type')),
                dn: $dn,
                entryUuid: $this->stringColumn($row, 'entry_uuid'),
                authzId: AuthzId::fromString($this->stringColumn($row, 'authz_id')),
                previousDn: $previousDn,
                preImage: $this->decodePreImage($row['pre_image'] ?? null, $dn),
            ),
        );
    }

    /**
     * @param array<array-key, mixed> $row
     */
    private function stringColumn(
        array $row,
        string $key,
    ): string {
        $value = $row[$key] ?? null;

        return is_scalar($value)
            ? (string) $value
            : '';
    }

    /**
     * @param array<array-key, mixed> $row
     */
    private function intColumn(
        array $row,
        string $key,
    ): int {
        $value = $row[$key] ?? null;

        return is_numeric($value)
            ? (int) $value
            : 0;
    }

    private function encodePreImage(?Entry $preImage): ?string
    {
        if ($preImage === null) {
            return null;
        }

        return serialize($preImage->toArray());
    }

    private function decodePreImage(
        mixed $encoded,
        Dn $dn,
    ): ?Entry {
        if (!is_string($encoded)) {
            return null;
        }

        /** @var array<string, list<string>> $attributes */
        $attributes = unserialize(
            $encoded,
            ['allowed_classes' => false],
        );

        return Entry::fromArray(
            $dn->toString(),
            $attributes,
        );
    }

    /**
     * @return Generator<ChangeRecord>
     */
    private function streamRecords(PooledStatement $stmt): Generator
    {
        while (($row = $stmt->fetch()) !== false) {
            if (is_array($row)) {
                yield $this->toRecord($row);
            }
        }
    }
}
