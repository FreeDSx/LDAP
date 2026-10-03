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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoRowLockDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
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
 * Replica-local password-policy state persisted as a JSON row per entryUUID.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PdoReplicaPasswordStateStore implements ReplicaPasswordStateStoreInterface
{
    use PdoColumnCastTrait;

    private const TABLE = 'ldap_replica_pwpolicy_state';

    public function __construct(
        private PdoConnection $connection,
        private PdoRowLockDialectInterface $dialect,
    ) {}

    public function load(string $uuid): ReplicaPasswordState
    {
        return $this->recordFor($uuid)->state ?? ReplicaPasswordState::empty();
    }

    /**
     * @param callable(ReplicaPasswordState): OperationalChanges $merge
     */
    public function atomicMutate(
        string $uuid,
        callable $merge,
    ): void {
        $this->connection->atomic(function () use ($uuid, $merge): void {
            $this->lockStateRow($uuid);

            $record = $this->recordFor($uuid);
            if ($record === null) {
                return;
            }

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
        $statement = $this->connection->execute(
            <<<SQL
                SELECT s.entry_uuid, e.lc_dn, s.state, s.seq, s.forwarded_seq
                FROM $table s
                INNER JOIN entries e ON e.entry_uuid = s.entry_uuid
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
                $this->stringColumn($row['entry_uuid']),
                new Dn($this->stringColumn($row['lc_dn'])),
                $this->decode($this->stringColumn($row['state'])),
                $this->intColumn($row['seq']),
                $this->intColumn($row['forwarded_seq']),
            );
        }

        return $pending;
    }

    public function markForwarded(
        string $uuid,
        int $sequence,
    ): void {
        $table = self::TABLE;
        $this->connection->execute(
            <<<SQL
                UPDATE $table
                SET forwarded_seq = ?
                WHERE entry_uuid = ? AND forwarded_seq < ? AND seq >= ?
                SQL,
            [
                $sequence,
                $uuid,
                $sequence,
                $sequence,
            ],
        );
    }

    /**
     * The row lock plus re-load makes the supersession check atomic, so a failure from a racing bind is never dropped.
     */
    public function discardIfSuperseded(
        string $uuid,
        UserPasswordState $authoritative,
    ): void {
        $this->connection->atomic(function () use ($uuid, $authoritative): void {
            $this->lockStateRow($uuid);

            $record = $this->recordFor($uuid);
            if ($record === null) {
                return;
            }

            $local = $record->state->toUserPasswordState($record->dn);
            if (!$local->isSupersededBy($authoritative)) {
                return;
            }

            $this->deleteRow($uuid);
        });
    }

    private function deleteRow(string $uuid): void
    {
        $table = self::TABLE;
        $this->connection->execute(
            <<<SQL
                DELETE FROM $table
                WHERE entry_uuid = ?
                SQL,
            [$uuid],
        );
    }

    private function recordFor(string $uuid): ?ReplicaForwardState
    {
        $table = self::TABLE;
        $row = $this->connection
            ->execute(
                <<<SQL
                    SELECT e.lc_dn, s.state, s.seq, s.forwarded_seq
                    FROM entries e
                    LEFT JOIN $table s ON s.entry_uuid = e.entry_uuid
                    WHERE e.entry_uuid = ?
                    SQL,
                [$uuid],
            )
            ->fetch();
        if (!is_array($row)) {
            return null;
        }

        $dn = new Dn($this->stringColumn($row['lc_dn']));
        if ($row['state'] === null) {
            return ReplicaForwardState::initial(
                $uuid,
                $dn,
            );
        }

        return new ReplicaForwardState(
            $uuid,
            $dn,
            $this->decode($this->stringColumn($row['state'])),
            $this->intColumn($row['seq']),
            $this->intColumn($row['forwarded_seq']),
        );
    }

    private function upsert(ReplicaForwardState $record): void
    {
        $this->deleteRow($record->uuid);
        $table = self::TABLE;
        $this->connection->execute(
            <<<SQL
                INSERT INTO $table (entry_uuid, state, seq, forwarded_seq)
                VALUES (?, ?, ?, ?)
                SQL,
            [
                $record->uuid,
                $this->encode($record->state),
                $record->sequence,
                $record->forwarded,
            ],
        );
    }

    private function lockStateRow(string $uuid): void
    {
        $this->dialect->lockRowForWrite(
            $this->connection->pdo(),
            self::TABLE,
            'entry_uuid',
            $uuid,
        );
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
