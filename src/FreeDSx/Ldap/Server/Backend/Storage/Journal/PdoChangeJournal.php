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
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Clock\EpochMicroseconds;
use FreeDSx\Ldap\Server\Clock\SystemClock;
use Generator;
use PDO;
use PDOStatement;

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
        private ReplicaId $origin = new ReplicaId('local'),
        private ClockInterface $clock = new SystemClock(),
    ) {}

    public function append(PendingChange $change): ChangeRecord
    {
        $createdAt = $this->clock->now();
        $normDn = $change->dn->normalize();
        $seq = 0;

        $this->transactor->atomic(function () use ($change, $normDn, $createdAt, &$seq): void {
            $pdo = $this->transactor->pdo();
            $pdo->prepare($this->dialect->queryJournalSeqBump())->execute();

            $read = $pdo->prepare($this->dialect->queryJournalSeqRead());
            $read->execute();
            $seq = (int) $read->fetchColumn();

            $pdo->prepare($this->dialect->queryJournalInsert())->execute([
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
        $stmt = $this->transactor->pdo()->prepare($this->dialect->queryJournalReadSince());
        $stmt->execute([$afterSeq]);

        return $this->streamRecords($stmt);
    }

    public function latestSeq(): int
    {
        $stmt = $this->transactor->pdo()->prepare($this->dialect->queryJournalSeqRead());
        $stmt->execute();

        return (int) $stmt->fetchColumn();
    }

    public function retainsSince(int $afterSeq): bool
    {
        $stmt = $this->transactor->pdo()->prepare($this->dialect->queryJournalMinSeq());
        $stmt->execute();
        $minSeq = $stmt->fetchColumn();

        // Empty journal: only a consumer already at the high-water mark is retained (mirrors InMemoryChangeJournal).
        if ($minSeq === null || $minSeq === false) {
            return $afterSeq >= $this->latestSeq();
        }

        return $afterSeq + 1 >= (int) $minSeq;
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
        $pdo = $this->transactor->pdo();
        $floor = $pdo->prepare($this->dialect->queryJournalKeepFloor());
        $floor->bindValue(1, $maxRecords - 1, PDO::PARAM_INT);
        $floor->execute();
        $keepFrom = $floor->fetchColumn();

        if ($keepFrom === false || $keepFrom === null) {
            return 0;
        }

        $delete = $pdo->prepare($this->dialect->queryJournalDeleteBelow());
        $delete->execute([$keepFrom]);

        return $delete->rowCount();
    }

    private function pruneToAgeWindow(int $maxAgeSeconds): int
    {
        $cutoff = EpochMicroseconds::fromSeconds($this->clock->now()->getTimestamp() - $maxAgeSeconds);
        $delete = $this->transactor->pdo()->prepare($this->dialect->queryJournalDeleteByAge());
        $delete->execute([$cutoff]);

        return $delete->rowCount();
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
    private function streamRecords(PDOStatement $stmt): Generator
    {
        while (($row = $stmt->fetch()) !== false) {
            if (is_array($row)) {
                yield $this->toRecord($row);
            }
        }
    }
}
