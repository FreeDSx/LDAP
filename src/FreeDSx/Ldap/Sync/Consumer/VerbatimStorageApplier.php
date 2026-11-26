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
use FreeDSx\Ldap\Server\Backend\Storage\Capability\DeferredLinksInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;

use function array_map;
use function array_push;
use function strtolower;
use function uasort;

/**
 * Applies sync results verbatim to a local replica's raw storage, reconciling deletes by absence.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class VerbatimStorageApplier implements ChangeApplierInterface
{
    /**
     * Bounds the passes that move entries back, each of which reads every entry's UUID.
     */
    private const MAX_PUT_BACK_PASSES = 8;

    /**
     * @var array<string, string> The DN each lower-cased UUID was announced at during the current refresh phase, or an empty string when announced by UUID alone.
     *
     * @todo Held entirely in memory, so a full refresh of a very large directory is costly. Should be refactored to a
     *       threshold-based on-disk (or generation-marked) present-set.
     */
    private array $announced = [];

    public function __construct(
        private readonly ListEntryInterface $lister,
        private readonly WriteEntryInterface $writer,
        private readonly ReadEntryInterface $reader,
        private readonly TransactionalWriteInterface $transaction,
        private readonly ReplicaMoves $moves,
        private readonly DeferredLinksInterface $links,
        private readonly LinkedValueFilter $linkedValues,
    ) {}

    public function beginRefresh(): void
    {
        $this->announced = [];
    }

    public function apply(
        SyncEntryResult $result,
        Session $session,
    ): void {
        $uuid = $result->getDecodedEntryUuid();

        // RFC 4533 §3.6: a delete names its entry by UUID, and its DN may be a past one or empty.
        if ($result->isDelete()) {
            $this->removeByUuids([$uuid]);

            return;
        }

        if (!$session->isRefreshComplete()) {
            $this->announced[strtolower($uuid)] = $result->getEntry()->getDn()->toString();
        }

        if ($result->isPresent()) {
            return;
        }

        $entry = $this->linkedValues->storable($this->identified(
            $result->getEntry(),
            $uuid,
        ));

        // RFC 4533 §3.6 keys entries by UUID, which makes the same one arriving elsewhere a move rather than a new entry.
        $this->transaction->atomic(function () use ($entry, $uuid, $session): void {
            $this->place(
                $uuid,
                $entry,
                $session,
            );
        });
    }

    public function applyIdSet(
        SyncIdSetResult $result,
        Session $session,
    ): void {
        $uuids = $result->getDecodedEntryUuids();

        if ($result->isDeleted()) {
            $this->removeByUuids($uuids);

            return;
        }

        // A present set only feeds the sweep, so it is worthless once the refresh that would run it is over.
        if ($session->isRefreshComplete()) {
            return;
        }

        foreach ($uuids as $uuid) {
            $this->announced[strtolower($uuid)] ??= '';
        }
    }

    public function reconcile(): void
    {
        [$stale, $unplaced] = $this->putBackAll();

        foreach ($stale as $dn) {
            $this->writer->remove($dn);
        }

        // Removing stale entries can free the DNs entries could not be moved back to.
        if ($unplaced !== [] && $stale !== []) {
            [, $unplaced] = $this->putBackAll();
        }
        $this->announced = [];

        if ($unplaced !== []) {
            throw new UnresolvedReplicaMovesException($unplaced);
        }
    }

    public function settle(): void
    {
        $this->moves->settle();
    }

    public function completeRefresh(): void
    {
        // Each batch commits on its own, and one cut short is linked at the end of the next refresh.
        do {
            $more = $this->transaction->atomic(fn(): bool => $this->links->linkDeferred());
        } while ($more);
    }

    /**
     * A refresh holds linked values back, as the entry at a DN they name may be one it has yet to move aside.
     *
     * @throws UnresolvedReplicaMovesException
     */
    private function place(
        string $uuid,
        Entry $entry,
        Session $session,
    ): void {
        $place = function (Entry $entry, LinkDelta $links) use ($uuid): void {
            $this->moves->place(
                $uuid,
                $entry,
                $links,
            );
        };

        if ($session->isRefreshComplete()) {
            $place(
                $entry,
                new LinkDelta(),
            );

            return;
        }

        $this->links->deferLinks(
            $uuid,
            $entry,
            $place,
        );
    }

    /**
     * @param string[] $uuids
     */
    private function removeByUuids(array $uuids): void
    {
        $removed = [];

        // Every DN is resolved before any is deleted, so the whole set goes out as one bulk delete.
        foreach ($uuids as $uuid) {
            $dn = $this->dnHolding($uuid);

            // The replica never held it, so there is nothing to delete.
            if ($dn === null) {
                continue;
            }

            $removed[] = $dn;
        }

        $this->writer->removeAll($removed);
    }

    /**
     * Sorts the local entries into those the refresh never announced and those it announced at another DN.
     *
     * @return array{list<Dn>, array<string, string>}
     */
    private function scan(): array
    {
        $options = StorageListOptions::matchAll(
            new Dn(''),
            subtree: true,
            projection: $this->uuidOnly(),
        );

        $stale = [];
        $misplaced = [];
        foreach ($this->lister->list($options)->entries() as $entry) {
            $uuid = $entry->getUuid();
            $announced = $this->announcedAt($uuid);

            if ($uuid === null || $announced === null) {
                $stale[] = $entry->getDn()->normalize();

                continue;
            }
            if (!$this->isAt($entry->getDn(), $announced)) {
                $misplaced[$uuid] = $announced;
            }
        }

        return [$stale, $misplaced];
    }

    /**
     * Moves entries back until a pass moves none, as moving one back can carry its children away.
     *
     * @return array{list<Dn>, list<string>} the stale entries, and the DNs nothing could be moved back to
     */
    private function putBackAll(): array
    {
        [$stale, $misplaced] = $this->scan();
        $unplaced = [];
        $passes = 0;

        while ($misplaced !== []) {
            if (++$passes > self::MAX_PUT_BACK_PASSES) {
                return [
                    $stale,
                    $this->stillAway($misplaced),
                ];
            }
            [$unplaced, $moved] = $this->putBack($misplaced);

            if (!$moved) {
                break;
            }
            // Stale entries are found again, as putting entries back can move them aside.
            [$stale, $misplaced] = $this->scan();
        }

        return [
            $stale,
            $misplaced === [] ? [] : $unplaced,
        ];
    }

    /**
     * The DNs of the entries still away from where they were announced, other than those left to another entry.
     *
     * @param array<string, string> $misplaced the announced DNs, keyed by lower-cased UUID
     *
     * @return list<string>
     */
    private function stillAway(array $misplaced): array
    {
        $away = [];

        foreach ($misplaced as $announced) {
            $target = (new Dn($announced))->normalize();

            if (!$this->isHeldWhereAnnounced($target)) {
                $away[] = $target->toString();
            }
        }

        return $away;
    }

    /**
     * Moves each entry back to the DN it was announced at, parents before their children.
     *
     * @param array<string, string> $misplaced the announced DNs, keyed by lower-cased UUID
     *
     * @return array{list<string>, bool} the DNs nothing could be moved back to, and whether any entry moved
     */
    private function putBack(array $misplaced): array
    {
        $targets = array_map(
            static fn(string $dn): Dn => (new Dn($dn))->normalize(),
            $misplaced,
        );
        uasort(
            $targets,
            static fn(
                Dn $a,
                Dn $b,
            ): int => $a->count() <=> $b->count(),
        );

        $unplaced = [];
        $moved = false;
        foreach ($targets as $uuid => $target) {
            try {
                $moved = $this->moveBack(
                    $uuid,
                    $target,
                ) || $moved;
            } catch (UnresolvedReplicaMovesException $e) {
                array_push(
                    $unplaced,
                    ...$e->dns,
                );
            }
        }

        return [
            $unplaced,
            $moved,
        ];
    }

    /**
     * Leaves the DN to an entry announced there, as a refresh also streams the changes made while it runs.
     *
     * @return bool whether the entry was moved
     *
     * @throws UnresolvedReplicaMovesException
     */
    private function moveBack(
        string $uuid,
        Dn $target,
    ): bool {
        if ($this->isHeldWhereAnnounced($target)) {
            return false;
        }

        $this->transaction->atomic(function () use ($uuid, $target): void {
            $this->moves->relocate(
                $uuid,
                $target,
            );
        });

        return true;
    }

    private function isHeldWhereAnnounced(Dn $dn): bool
    {
        $occupant = $this->reader->find(
            $dn,
            $this->uuidOnly(),
        );
        $announced = $this->announcedAt($occupant?->getUuid());

        return $announced !== null && $this->isAt(
            $dn,
            $announced,
        );
    }

    /**
     * The DN the refresh announced the entry at, or null when it did not announce it.
     */
    private function announcedAt(?string $uuid): ?string
    {
        return $uuid === null
            ? null
            : $this->announced[$uuid] ?? null;
    }

    /**
     * Whether the DN is where the entry was announced, which an announcement by UUID alone leaves open.
     */
    private function isAt(
        Dn $dn,
        string $announced,
    ): bool {
        return $announced === ''
            || $dn->toString() === $announced
            || $dn->normalizedString() === Dn::normalized($announced);
    }

    private function uuidOnly(): EntryProjection
    {
        return new EntryProjection(
            [strtolower(AttributeTypeOid::NAME_ENTRY_UUID)],
            linkCap: 0,
        );
    }

    /**
     * Where this replica already holds the entry with $uuid, or null when it holds it nowhere.
     */
    private function dnHolding(string $uuid): ?Dn
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
     * The entry carrying its UUID, since a narrowed selection strips it and an entry without one cannot be correlated.
     */
    private function identified(
        Entry $entry,
        string $uuid,
    ): Entry {
        if ($entry->has(AttributeTypeOid::NAME_ENTRY_UUID)) {
            return $entry;
        }

        $copy = $entry->makeCopy();
        $copy->set(
            AttributeTypeOid::NAME_ENTRY_UUID,
            $uuid,
        );

        return $copy;
    }
}
