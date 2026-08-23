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
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;

/**
 * Applies sync results verbatim to a local replica's raw storage, reconciling deletes by absence.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class VerbatimStorageApplier implements ChangeApplierInterface
{
    /**
     * @var array<string, true> Normalized DNs seen during the current refresh phase.
     *
     * @todo Held entirely in memory, so a full refresh of a very large directory is costly. Should be refactored to a
     *       threshold-based on-disk (or generation-marked) present-set.
     */
    private array $presentDns = [];

    public function __construct(private readonly EntryStorageInterface $storage) {}

    public function beginRefresh(): void
    {
        $this->presentDns = [];
    }

    public function apply(
        SyncEntryResult $result,
        Session $session,
    ): void {
        $entry = $result->getEntry();
        $dn = $entry->getDn()
            ->normalize();

        if ($result->isDelete()) {
            $this->storage->remove($dn);

            return;
        }

        if (!$session->isRefreshComplete()) {
            $this->presentDns[$dn->toString()] = true;
        }

        if ($result->isPresent()) {
            return;
        }

        $uuid = $result->getDecodedEntryUuid();

        // RFC 4533 §3.6 keys entries by UUID, so the same one arriving elsewhere is a move rather than a new entry.
        $heldAt = $this->dnHolding($uuid);

        if ($heldAt !== null && $heldAt->toString() !== $dn->toString()) {
            $this->storage->remove($heldAt);
        }

        $this->storage->store($this->identified($entry, $uuid));
    }

    public function reconcile(): void
    {
        $options = StorageListOptions::matchAll(
            new Dn(''),
            subtree: true,
        );

        $stale = [];
        foreach ($this->storage->list($options)->entries as $entry) {
            $dn = $entry->getDn()
                ->normalize();

            if (!isset($this->presentDns[$dn->toString()])) {
                $stale[] = $dn;
            }
        }

        foreach ($stale as $dn) {
            $this->storage->remove($dn);
        }

        $this->presentDns = [];
    }

    /**
     * Where this replica already holds the entry with $uuid, or null when it holds it nowhere.
     */
    private function dnHolding(string $uuid): ?Dn
    {
        $options = new StorageListOptions(
            baseDn: new Dn(''),
            subtree: true,
            filter: Filters::equal(
                AttributeTypeOid::NAME_ENTRY_UUID,
                $uuid,
            ),
        );

        // Storage answers the filter only where it can, so each candidate is checked rather than trusted.
        foreach ($this->storage->list($options)->entries as $entry) {
            if ($entry->get(AttributeTypeOid::NAME_ENTRY_UUID)?->firstValue() !== $uuid) {
                continue;
            }

            return $entry->getDn()
                ->normalize();
        }

        return null;
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
