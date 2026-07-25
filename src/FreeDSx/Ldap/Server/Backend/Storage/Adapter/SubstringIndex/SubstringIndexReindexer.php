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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Backfills the substring index by re-storing every entry; run it after enabling indexing on an existing directory or changing the indexed attributes.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SubstringIndexReindexer
{
    public function __construct(
        private EntryStorageInterface $storage,
    ) {}

    /**
     * Re-store every entry in one transaction via raw storage: the substring index is rebuilt while operational attributes are preserved verbatim and no change is journaled.
     */
    public function reindex(): void
    {
        $dns = $this->collectDns();

        $this->storage->atomic(function () use ($dns): void {
            foreach ($dns as $dn) {
                $entry = $this->storage->find($dn);
                if ($entry === null) {
                    continue;
                }

                $this->storage->store(
                    $entry,
                    rebuildIndexes: true,
                );
            }
        });
    }

    /**
     * Drain the entry DNs up front so the entries table is not being read while it is re-stored.
     *
     * @return list<Dn>
     */
    private function collectDns(): array
    {
        $dns = [];
        foreach ($this->storage->namingContexts() as $namingContext) {
            $stream = $this->storage->list(StorageListOptions::matchAll(
                $namingContext,
                true,
            ));

            foreach ($stream->entries as $entry) {
                $dns[] = $entry->getDn();
            }
        }

        return $dns;
    }
}
