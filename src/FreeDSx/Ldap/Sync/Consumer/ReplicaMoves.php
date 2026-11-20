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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\SubtreeRename;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\EntryAlreadyExistsException;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

use function ksort;
use function strtolower;

/**
 * Places replicated entries by entryUUID, moving aside any entry in the way rather than overwriting it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ReplicaMoves
{
    /**
     * @var array<string, string> the DN each entry was moved aside from, keyed by lowercased entryUUID
     */
    private array $parked = [];

    /**
     * @var array<string, true> the parked entries already carried over one sync point, keyed by lowercased entryUUID
     */
    private array $carried = [];

    public function __construct(
        private readonly ReadEntryInterface $reader,
        private readonly ListEntryInterface $lister,
        private readonly WriteEntryInterface $writer,
    ) {}

    /**
     * Writes the entry at its DN, renaming the subtree it already heads there when it held another DN.
     *
     * @throws UnresolvedReplicaMovesException when an entry in the way cannot be moved aside
     */
    public function place(
        string $uuid,
        Entry $entry,
    ): void {
        $heldAt = $this->heldAt($uuid);

        if ($heldAt === null) {
            $this->add($entry);

            return;
        }

        $target = $entry->getDn()->normalize();
        if ($heldAt->toString() !== $target->toString()) {
            $this->move(
                $uuid,
                $heldAt,
                $target,
            );
        }

        $this->writer->store($entry);
        $this->forget($uuid);
    }

    /**
     * Moves the entry and the subtree it heads to the DN, when something carried it elsewhere after it was placed.
     *
     * @throws UnresolvedReplicaMovesException when an entry in the way cannot be moved aside
     */
    public function relocate(
        string $uuid,
        Dn $target,
    ): void {
        $heldAt = $this->heldAt($uuid);

        if ($heldAt === null || $heldAt->toString() === $target->toString()) {
            return;
        }

        $this->move(
            $uuid,
            $heldAt,
            $target,
        );
        $this->forget($uuid);
    }

    /**
     * Reports the entries moved aside that no change placed again by their second sync point, as a change can be read a window late.
     *
     * @throws UnresolvedReplicaMovesException naming the DNs those entries were moved aside from
     */
    public function settle(): void
    {
        $unplaced = [];

        foreach ($this->parked as $uuid => $dn) {
            if (!$this->isParked($uuid)) {
                $this->forget($uuid);

                continue;
            }
            if (!isset($this->carried[$uuid])) {
                $this->carried[$uuid] = true;

                continue;
            }

            $unplaced[] = $dn;
            $this->forget($uuid);
        }

        if ($unplaced !== []) {
            throw new UnresolvedReplicaMovesException($unplaced);
        }
    }

    /**
     * @throws UnresolvedReplicaMovesException
     */
    private function add(Entry $entry): void
    {
        try {
            $this->writer->insert($entry);

            return;
        } catch (EntryAlreadyExistsException) {
            // Another entry still holds the DN, as its own change has not arrived yet.
        }

        $this->moveAside($entry->getDn()->normalize());
        $this->writer->insert($entry);
    }

    /**
     * @throws UnresolvedReplicaMovesException
     */
    private function move(
        string $uuid,
        Dn $heldAt,
        Dn $target,
    ): void {
        $heldAt = $this->clearTarget(
            $uuid,
            $heldAt,
            $target,
        );

        try {
            $this->writer->renameSubtree(
                $heldAt,
                $target,
            );

            return;
        } catch (EntryAlreadyExistsException) {
            // A descendant lands on an entry outside the subtree, which is rare enough to search for only now.
        }

        $this->moveAsideLandings(
            $heldAt,
            $target,
        );
        $this->renameOrFail(
            $uuid,
            $target,
        );
    }

    /**
     * Where the entry moves from once nothing holds the target and the target does not sit under it.
     *
     * @throws UnresolvedReplicaMovesException
     */
    private function clearTarget(
        string $uuid,
        Dn $heldAt,
        Dn $target,
    ): Dn {
        if ($this->moveAside($target)) {
            $heldAt = $this->heldAtOrFail(
                $uuid,
                $target,
            );
        }

        // The entry steps aside first, as a subtree cannot move under itself.
        return $target->isDescendantOf($heldAt)
            ? $this->park(
                $uuid,
                $heldAt,
            )
            : $heldAt;
    }

    /**
     * @throws UnresolvedReplicaMovesException when the target or a DN under it is still taken
     */
    private function renameOrFail(
        string $uuid,
        Dn $target,
    ): void {
        try {
            $this->writer->renameSubtree(
                $this->heldAtOrFail(
                    $uuid,
                    $target,
                ),
                $target,
            );
        } catch (EntryAlreadyExistsException) {
            throw new UnresolvedReplicaMovesException([$target->toString()]);
        }
    }

    /**
     * Moves aside the entry holding the DN, if any.
     *
     * @throws UnresolvedReplicaMovesException
     */
    private function moveAside(Dn $dn): bool
    {
        $occupant = $this->occupantOf($dn);
        if ($occupant === null) {
            return false;
        }

        $this->park(
            $occupant,
            $dn,
        );

        return true;
    }

    /**
     * Moves aside each entry a descendant of the subtree would land on, shallowest first.
     *
     * @throws UnresolvedReplicaMovesException
     */
    private function moveAsideLandings(
        Dn $heldAt,
        Dn $target,
    ): void {
        // Each depth is read after the last, as moving an occupant aside takes any deeper one with it.
        foreach ($this->landingsByDepth($heldAt, $target) as $landings) {
            $occupants = $this->lister->entriesAt(
                $landings,
                $this->uuidOnly(),
            );

            foreach ($occupants as $occupant) {
                $this->park(
                    $occupant->getUuidOrFail(),
                    $occupant->getDn()->normalize(),
                );
            }
        }
    }

    /**
     * Where each descendant the storage would carry lands, grouped by depth, shallowest first.
     *
     * @return array<int, list<Dn>>
     */
    private function landingsByDepth(
        Dn $heldAt,
        Dn $target,
    ): array {
        $rename = new SubtreeRename(
            $heldAt,
            $target,
            $heldAt->toString(),
        );
        // The listing holds what the storage carries, including an entry whose parent is not stored.
        $options = StorageListOptions::matchAll(
            $heldAt,
            subtree: true,
            projection: $this->uuidOnly(),
        );
        $landings = [];

        foreach ($this->lister->list($options)->entries() as $descendant) {
            $lcDn = $descendant->getDn()->normalizedString();

            if ($lcDn === $rename->lcFrom) {
                continue;
            }
            $landing = Dn::fromCanonical($rename->canonicalFor($lcDn));
            $landings[$landing->count()][] = $landing;
        }
        ksort($landings);

        return $landings;
    }

    /**
     * Moves the entry and its subtree aside to a sibling DN named by its own UUID, which only that entry can validly hold.
     *
     * @throws UnresolvedReplicaMovesException when another entry already holds that DN
     */
    private function park(
        string $uuid,
        Dn $heldAt,
    ): Dn {
        $slot = $this->slotOf(
            $uuid,
            $heldAt,
        );
        $this->parked[strtolower($uuid)] = $heldAt->toString();

        if ($slot->toString() === $heldAt->toString()) {
            return $slot;
        }
        if ($this->reader->exists($slot)) {
            throw new UnresolvedReplicaMovesException([$heldAt->toString()]);
        }

        $this->writer->renameSubtree(
            $heldAt,
            $slot,
        );

        return $slot;
    }

    private function isParked(string $uuid): bool
    {
        $heldAt = $this->heldAt($uuid);

        if ($heldAt === null) {
            return false;
        }

        $slot = $this->slotOf(
            $uuid,
            $heldAt,
        );

        return $slot->toString() === $heldAt->toString();
    }

    private function forget(string $uuid): void
    {
        $key = strtolower($uuid);

        unset(
            $this->parked[$key],
            $this->carried[$key],
        );
    }

    private function slotOf(
        string $uuid,
        Dn $heldAt,
    ): Dn {
        $rdn = 'entryUUID=' . $uuid;
        $parent = $heldAt->getParent();

        return (new Dn($parent === null ? $rdn : $rdn . ',' . $parent->toString()))->normalize();
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

    /**
     * Where the entry is after a move aside carried it along.
     *
     * @throws UnresolvedReplicaMovesException when the entry is no longer held anywhere
     */
    private function heldAtOrFail(
        string $uuid,
        Dn $target,
    ): Dn {
        return $this->heldAt($uuid) ?? throw new UnresolvedReplicaMovesException([$target->toString()]);
    }

    private function occupantOf(Dn $dn): ?string
    {
        return $this->reader
            ->find(
                $dn,
                $this->uuidOnly(),
            )
            ?->getUuid();
    }

    private function uuidOnly(): EntryProjection
    {
        return new EntryProjection(
            [strtolower(AttributeTypeOid::NAME_ENTRY_UUID)],
            linkCap: 0,
        );
    }
}
