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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoEntryDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaForwardState;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordState;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

use function is_array;
use function json_decode;
use function json_encode;
use function max;

/**
 * Replica-local password-policy state persisted as a JSON row per subject, sharing a PdoStorage connection.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PdoReplicaPasswordStateStore implements ReplicaPasswordStateStoreInterface
{
    use PdoColumnCastTrait;

    private const TABLE = 'ldap_replica_pwpolicy_state';

    public function __construct(
        private PdoTransactor $transactor,
        private PdoEntryDialectInterface $dialect,
        private PdoStatementPool $statements,
    ) {}

    public function load(Dn $dn): ReplicaPasswordState
    {
        return $this->loadRecord($dn)->state;
    }

    /**
     * @param callable(ReplicaPasswordState): OperationalChanges $merge
     */
    public function atomicMutate(
        Dn $dn,
        callable $merge,
    ): void {
        $this->transactor->atomic(function () use ($dn, $merge): void {
            $this->lockStateRow($dn);

            $record = $this->loadRecord($dn);
            $changes = $merge($record->state);
            if ($changes->isEmpty()) {
                return;
            }

            $next = $record->state->withChanges($changes);
            if ($record->state->equals($next)) {
                return;
            }

            $this->upsert($record->applied($next));
        });
    }

    public function listUnforwarded(int $limit = 100): array
    {
        $table = self::TABLE;
        $statement = $this->statements->execute(
            <<<SQL
                SELECT e.lc_dn, s.state, s.seq, s.forwarded_seq
                FROM $table s
                INNER JOIN entries e ON e.entry_id = s.entry_id
                WHERE s.seq > s.forwarded_seq
                ORDER BY s.seq ASC
                LIMIT ?
                SQL,
            [max(0, $limit)],
        );

        $pending = [];
        while (($row = $statement->fetch()) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $pending[] = new ReplicaForwardState(
                new Dn($this->stringColumn($row['lc_dn'])),
                $this->decode($this->stringColumn($row['state'])),
                $this->intColumn($row['seq']),
                $this->intColumn($row['forwarded_seq']),
            );
        }

        return $pending;
    }

    public function markForwarded(
        Dn $dn,
        int $sequence,
    ): void {
        $entryId = $this->entryId($dn);

        if ($entryId === null) {
            return;
        }

        $table = self::TABLE;
        $this->statements->execute(
            <<<SQL
                UPDATE $table
                SET forwarded_seq = ?
                WHERE entry_id = ? AND forwarded_seq < ? AND seq >= ?
                SQL,
            [
                $sequence,
                $entryId,
                $sequence,
                $sequence,
            ],
        );
    }

    /**
     * The row lock plus re-load makes the supersession check atomic, so a failure from a racing bind is never dropped.
     */
    public function discardIfSuperseded(
        Dn $dn,
        UserPasswordState $authoritative,
    ): void {
        $this->transactor->atomic(function () use ($dn, $authoritative): void {
            $this->lockStateRow($dn);

            $local = $this->loadRecord($dn)
                ->state
                ->toUserPasswordState($dn);
            if (!$local->isSupersededBy($authoritative)) {
                return;
            }

            $this->deleteRow($dn);
        });
    }

    public function discard(Dn $dn): void
    {
        $this->deleteRow($dn);
    }

    private function deleteRow(Dn $dn): void
    {
        $entryId = $this->entryId($dn);
        if ($entryId === null) {
            return;
        }

        $table = self::TABLE;
        $this->statements->execute(
            <<<SQL
                DELETE FROM $table
                WHERE entry_id = ?
                SQL,
            [$entryId],
        );
    }

    private function loadRecord(Dn $dn): ReplicaForwardState
    {
        $entryId = $this->entryId($dn);
        if ($entryId === null) {
            return ReplicaForwardState::initial($dn);
        }

        $table = self::TABLE;
        $row = $this->statements
            ->execute(
                <<<SQL
                    SELECT state, seq, forwarded_seq
                    FROM $table
                    WHERE entry_id = ?
                    SQL,
                [$entryId],
            )
            ->fetch();
        if (!is_array($row)) {
            return ReplicaForwardState::initial($dn);
        }

        return new ReplicaForwardState(
            $dn,
            $this->decode($this->stringColumn($row['state'])),
            $this->intColumn($row['seq']),
            $this->intColumn($row['forwarded_seq']),
        );
    }

    private function upsert(ReplicaForwardState $record): void
    {
        $entryId = $this->entryId($record->dn);
        if ($entryId === null) {
            throw new RuntimeException(sprintf(
                'Replica password state cannot be held for "%s", which this backend does not store.',
                $record->dn->toString(),
            ));
        }

        $this->deleteRow($record->dn);
        $table = self::TABLE;
        $this->statements->execute(
            <<<SQL
                INSERT INTO $table (entry_id, state, seq, forwarded_seq)
                VALUES (?, ?, ?, ?)
                SQL,
            [
                $entryId,
                $this->encode($record->state),
                $record->sequence,
                $record->forwarded,
            ],
        );
    }

    /**
     * A DN with no entry has no state row to lock, and loading it then yields the initial state.
     */
    private function lockStateRow(Dn $dn): void
    {
        $entryId = $this->entryId($dn);
        if ($entryId === null) {
            return;
        }

        $this->dialect->lockRowForWrite(
            $this->transactor->pdo(),
            self::TABLE,
            'entry_id',
            $entryId,
        );
    }

    /**
     * The state hangs off the entry key, so it survives a rename; null when this backend holds no such entry.
     */
    private function entryId(Dn $dn): ?int
    {
        $row = $this->statements
            ->execute(
                $this->dialect->queryEntryId(),
                [$dn->normalize()->toString()],
            )
            ->fetch();

        return is_array($row) && isset($row['entry_id'])
            ? $this->intColumn($row['entry_id'])
            : null;
    }

    private function encode(ReplicaPasswordState $state): string
    {
        $json = json_encode($state->toArray());
        if ($json === false) {
            throw new StorageIoException('Failed to encode replica password-policy state.');
        }

        return $json;
    }

    private function decode(string $state): ReplicaPasswordState
    {
        /** @var array<string, list<string>>|null $decoded */
        $decoded = json_decode(
            $state,
            true,
        );
        if (!is_array($decoded)) {
            throw new StorageIoException('Failed to decode replica password-policy state; storage row is corrupted.');
        }

        return ReplicaPasswordState::fromArray($decoded);
    }
}
