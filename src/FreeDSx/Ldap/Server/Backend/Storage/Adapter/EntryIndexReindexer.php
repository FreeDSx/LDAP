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
use FreeDSx\Ldap\Exception\InvalidDnSyntaxException;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\DnKeyRebuilderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnKeyCollisionException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Rebuilds every stored DN key and secondary index; run it after enabling substring indexing on an existing directory, changing the indexed attributes, changing an attribute's matching rules, or upgrading to a release that changes how DNs or values are normalized.
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
        private DnKeyRebuilderInterface $dnKeys,
    ) {}

    /**
     * Rebuild the DN keys, then re-store every entry in the same transaction via raw storage: the indexes are rebuilt while operational attributes are preserved verbatim and no change is journaled.
     *
     * @throws DnKeyCollisionException when two entries' DNs now share one key
     * @throws DnTooLongException when a rebuilt DN key exceeds what the storage holds
     * @throws InvalidDnSyntaxException when a stored DN no longer parses
     */
    public function reindex(): void
    {
        $this->transaction->atomic(function (): void {
            // Rebuilt first: every entry below is listed and read by its DN key.
            $this->dnKeys->rebuild();

            foreach ($this->collectDns() as $dn) {
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
