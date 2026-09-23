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
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Rebuilds every secondary index by re-storing each entry; run it after enabling substring indexing on an existing directory, changing the indexed attributes, or changing an attribute's matching rules.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryIndexReindexer
{
    public function __construct(
        private ReadEntryInterface $reader,
        private ListEntryInterface $lister,
        private WriteEntryInterface $writer,
        private TransactionalWriteInterface $transaction,
    ) {}

    /**
     * Re-store every entry in one transaction via raw storage: the indexes are rebuilt while operational attributes are preserved verbatim and no change is journaled.
     */
    public function reindex(): void
    {
        $dns = $this->collectDns();

        $this->transaction->atomic(function () use ($dns): void {
            foreach ($dns as $dn) {
                // re-indexing leaves links alone and never has to read them.
                $entry = $this->reader->find(
                    $dn,
                    new EntryProjection(linkCap: 0),
                );
                if ($entry === null) {
                    continue;
                }

                $this->writer->store(
                    $entry,
                    rebuildIndexes: true,
                    links: LinkDelta::untouched(),
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
        foreach ($this->reader->namingContexts() as $namingContext) {
            $stream = $this->lister->list(StorageListOptions::matchAll(
                $namingContext,
                subtree: true,
                projection: new EntryProjection([]),
            ));

            foreach ($stream->entries() as $entry) {
                $dns[] = $entry->getDn();
            }
        }

        return $dns;
    }
}
