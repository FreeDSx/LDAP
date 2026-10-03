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

namespace FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\UnresolvedReplicaMovesException;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;

use function array_diff_key;
use function array_keys;
use function array_map;
use function array_values;
use function count;
use function strtolower;

/**
 * Applies replicated moves as renames and handles deferrals.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ReplicaMoves
{
    /**
     * More deferred moves than this in one window is treated as a disagreement which needs a refresh.
     */
    private const LIMIT = 1000;

    /**
     * @var array<string, Entry> the entry each deferred move places, keyed by lowercased entryUUID
     */
    private array $deferred = [];

    public function __construct(
        private readonly ReadEntryInterface $reader,
        private readonly WriteEntryInterface $writer,
        private readonly TransactionalWriteInterface $transaction,
    ) {}

    /**
     * Renames the entry at $heldAt, with its subtree, to the entry's DN, keeping everything that hangs off its identity.
     *
     * @throws UnresolvedReplicaMovesException when more moves are deferred than one window may hold
     */
    public function move(
        string $uuid,
        Dn $heldAt,
        Entry $entry,
    ): void {
        if ($this->reader->exists($entry->getDn())) {
            $this->defer(
                $uuid,
                $entry,
            );

            return;
        }

        $this->relocate(
            $heldAt,
            $entry,
        );
    }

    /**
     * A newer message for the entry supersedes its deferred move.
     */
    public function forget(string $uuid): void
    {
        unset($this->deferred[strtolower($uuid)]);
    }

    public function clear(): void
    {
        $this->deferred = [];
    }

    /**
     * Places every deferred move it can, and reports the rest.
     *
     * @throws UnresolvedReplicaMovesException naming the moves whose new DN an entry with no pending move still holds
     */
    public function settle(): void
    {
        $this->placeResolvable();

        $this->throwIfAny();
    }

    /**
     * @throws UnresolvedReplicaMovesException
     */
    private function defer(
        string $uuid,
        Entry $entry,
    ): void {
        $this->deferred[strtolower($uuid)] = $entry;

        if (count($this->deferred) <= self::LIMIT) {
            return;
        }

        // Placed early, so only moves blocked by an entry with no pending move can fill the window.
        $this->placeResolvable();

        if (count($this->deferred) <= self::LIMIT) {
            return;
        }

        $this->throwIfAny();
    }

    /**
     * Places the resolvable moves in one transaction, through temporary DNs so chains and swaps resolve alike.
     *
     * @throws UnresolvedReplicaMovesException when malformed data holds a parking DN
     */
    private function placeResolvable(): void
    {
        if ($this->deferred === []) {
            return;
        }

        $resolvable = $this->resolvable();

        $this->transaction->atomic(function () use ($resolvable): void {
            foreach (array_keys($resolvable) as $uuid) {
                // Rolled back whole, so none of the moves was placed.
                if (!$this->park($uuid)) {
                    $this->throwIfAny();
                }
            }
            foreach ($resolvable as $uuid => $entry) {
                $this->relocate(
                    $this->heldAt($uuid),
                    $entry,
                );
            }
        });

        $this->deferred = array_diff_key(
            $this->deferred,
            $resolvable,
        );
    }

    /**
     * @throws UnresolvedReplicaMovesException naming every move still deferred
     */
    private function throwIfAny(): void
    {
        if ($this->deferred === []) {
            return;
        }

        $dns = $this->dnsOf($this->deferred);
        $this->deferred = [];

        throw new UnresolvedReplicaMovesException($dns);
    }

    /**
     * The deferred moves whose new DN is free, already theirs, or held by another of them. Found by dropping the rest
     * until none is left to drop.
     *
     * @return array<string, Entry>
     */
    private function resolvable(): array
    {
        $resolvable = $this->deferred;

        do {
            $dropped = false;

            foreach ($resolvable as $uuid => $entry) {
                $occupant = $this->occupantOf($entry->getDn());

                if ($occupant === null || $occupant === $uuid || isset($resolvable[$occupant])) {
                    continue;
                }

                unset($resolvable[$uuid]);
                $dropped = true;
            }
        } while ($dropped);

        return $resolvable;
    }

    /**
     * Moves the entry aside to a sibling DN named by its own UUID, false when malformed data already holds it.
     *
     * Only the entry with that UUID can validly be named by it.
     */
    private function park(string $uuid): bool
    {
        $heldAt = $this->heldAt($uuid);
        if ($heldAt === null) {
            return true;
        }

        $rdn = 'entryUUID=' . $uuid;
        $parent = $heldAt->getParent();
        $slot = new Dn($parent === null ? $rdn : $rdn . ',' . $parent->toString());

        // An entry already named by its own UUID is parked where it is.
        if ($slot->normalize()->toString() === $heldAt->toString()) {
            return true;
        }
        if ($this->reader->exists($slot)) {
            return false;
        }

        $this->writer->renameSubtree(
            $heldAt,
            $slot,
        );

        return true;
    }

    private function relocate(
        ?Dn $heldAt,
        Entry $entry,
    ): void {
        if ($heldAt !== null && $heldAt->toString() !== $entry->getDn()->normalize()->toString()) {
            $this->writer->renameSubtree(
                $heldAt,
                $entry->getDn(),
            );
        }

        $this->writer->store($entry);
    }

    private function heldAt(string $uuid): ?Dn
    {
        return $this->reader
            ->findByUuid(
                $uuid,
                new EntryProjection(
                    [],
                    linkCap: 0,
                ),
            )
            ?->getDn()
            ->normalize();
    }

    private function occupantOf(Dn $dn): ?string
    {
        return $this->reader
            ->find(
                $dn->normalize(),
                new EntryProjection(
                    [strtolower(AttributeTypeOid::NAME_ENTRY_UUID)],
                    linkCap: 0,
                ),
            )
            ?->getUuid();
    }

    /**
     * @param array<string, Entry> $moves
     * @return list<string>
     */
    private function dnsOf(array $moves): array
    {
        return array_values(array_map(
            static fn(Entry $entry): string => $entry->getDn()->toString(),
            $moves,
        ));
    }
}
