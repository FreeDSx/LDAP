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
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;

use function strtolower;

/**
 * Applies sync results verbatim to a local replica's raw storage, reconciling deletes by absence.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class VerbatimStorageApplier implements ChangeApplierInterface
{
    /**
     * @var array<string, true> Lower-cased UUIDs announced present during the current refresh phase.
     *
     * @todo Held entirely in memory, so a full refresh of a very large directory is costly. Should be refactored to a
     *       threshold-based on-disk (or generation-marked) present-set.
     */
    private array $presentUuids = [];

    public function __construct(
        private readonly ListEntryInterface $lister,
        private readonly WriteEntryInterface $writer,
        private readonly ReadEntryInterface $reader,
        private readonly TransactionalWriteInterface $transaction,
        private readonly ReplicaMoves $moves,
    ) {}

    public function beginRefresh(): void
    {
        $this->presentUuids = [];
        $this->moves->clear();
    }

    public function apply(
        SyncEntryResult $result,
        Session $session,
    ): void {
        $uuid = $result->getDecodedEntryUuid();
        $this->moves->forget($uuid);

        // RFC 4533 §3.6: a delete names its entry by UUID, and its DN may be a past one or empty.
        if ($result->isDelete()) {
            $this->removeByUuids([$uuid]);

            return;
        }

        if (!$session->isRefreshComplete()) {
            $this->presentUuids[strtolower($uuid)] = true;
        }

        if ($result->isPresent()) {
            return;
        }

        $entry = $this->identified(
            $result->getEntry(),
            $uuid,
        );

        $this->transaction->atomic(function () use ($entry, $uuid): void {
            $heldAt = $this->dnHolding($uuid);

            if ($heldAt === null || $heldAt->toString() === $entry->getDn()->normalize()->toString()) {
                $this->writer->store($entry);

                return;
            }

            // RFC 4533 §3.6 keys entries by UUID, so the same one arriving elsewhere is a move rather than a new entry.
            $this->moves->move(
                $uuid,
                $heldAt,
                $entry,
            );
        });
    }

    public function applyIdSet(
        SyncIdSetResult $result,
        Session $session,
    ): void {
        $uuids = $result->getDecodedEntryUuids();

        if ($result->isDeleted()) {
            foreach ($uuids as $uuid) {
                $this->moves->forget($uuid);
            }
            $this->removeByUuids($uuids);

            return;
        }

        // A present set only feeds the sweep, so it is worthless once the refresh that would run it is over.
        if ($session->isRefreshComplete()) {
            return;
        }

        foreach ($uuids as $uuid) {
            $this->presentUuids[strtolower($uuid)] = true;
        }
    }

    public function reconcile(): void
    {
        $options = StorageListOptions::matchAll(
            new Dn(''),
            subtree: true,
        );

        $stale = [];
        foreach ($this->lister->list($options)->entries() as $entry) {
            if (!$this->wasAnnouncedPresent($entry)) {
                $stale[] = $entry->getDn()->normalize();
            }
        }

        foreach ($stale as $dn) {
            $this->writer->remove($dn);
        }

        $this->presentUuids = [];
    }

    public function settle(): void
    {
        $this->moves->settle();
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
     * Whether the upstream announced this entry as still present, by the UUID that identifies it wherever it lives.
     */
    private function wasAnnouncedPresent(Entry $entry): bool
    {
        $uuid = $entry->getUuid();

        return $uuid !== null && isset($this->presentUuids[$uuid]);
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
