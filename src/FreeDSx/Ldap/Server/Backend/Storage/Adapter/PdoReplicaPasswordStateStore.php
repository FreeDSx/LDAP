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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoEntryDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaForwardState;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordState;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PDO;

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
            $this->dialect->lockRowForWrite(
                $this->transactor->pdo(),
                self::TABLE,
                $this->key($dn),
            );

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
        $statement = $this->transactor
            ->pdo()
            ->prepare(
                'SELECT lc_dn, state, seq, forwarded_seq FROM ' . self::TABLE
                . ' WHERE seq > forwarded_seq ORDER BY seq ASC LIMIT ' . max(0, $limit),
            );
        $statement->execute();

        $pending = [];
        /** @var array<string, mixed> $row */
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
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
        $this->transactor
            ->pdo()
            ->prepare(
                'UPDATE ' . self::TABLE
                . ' SET forwarded_seq = ? WHERE lc_dn = ? AND forwarded_seq < ? AND seq >= ?',
            )
            ->execute([
                $sequence,
                $this->key($dn),
                $sequence,
                $sequence,
            ]);
    }

    /**
     * The row lock plus re-load makes the supersession check atomic, so a failure from a racing bind is never dropped.
     */
    public function discardIfSuperseded(
        Dn $dn,
        UserPasswordState $authoritative,
    ): void {
        $this->transactor->atomic(function () use ($dn, $authoritative): void {
            $this->dialect->lockRowForWrite(
                $this->transactor->pdo(),
                self::TABLE,
                $this->key($dn),
            );

            $local = $this->loadRecord($dn)
                ->state
                ->toUserPasswordState($dn);
            if (!$local->isSupersededBy($authoritative)) {
                return;
            }

            $this->transactor
                ->pdo()
                ->prepare('DELETE FROM ' . self::TABLE . ' WHERE lc_dn = ?')
                ->execute([$this->key($dn)]);
        });
    }

    public function discard(Dn $dn): void
    {
        $this->transactor
            ->pdo()
            ->prepare('DELETE FROM ' . self::TABLE . ' WHERE lc_dn = ?')
            ->execute([$this->key($dn)]);
    }

    private function loadRecord(Dn $dn): ReplicaForwardState
    {
        $statement = $this->transactor
            ->pdo()
            ->prepare('SELECT state, seq, forwarded_seq FROM ' . self::TABLE . ' WHERE lc_dn = ?');
        $statement->execute([$this->key($dn)]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
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
        $key = $this->key($record->dn);
        $pdo = $this->transactor->pdo();

        $pdo->prepare('DELETE FROM ' . self::TABLE . ' WHERE lc_dn = ?')
            ->execute([$key]);
        $pdo->prepare('INSERT INTO ' . self::TABLE . ' (lc_dn, state, seq, forwarded_seq) VALUES (?, ?, ?, ?)')
            ->execute([
                $key,
                $this->encode($record->state),
                $record->sequence,
                $record->forwarded,
            ]);
    }

    private function key(Dn $dn): string
    {
        return $dn->normalize()->toString();
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
