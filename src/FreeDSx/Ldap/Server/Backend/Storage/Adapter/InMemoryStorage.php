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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\ArrayEntryStorageTrait;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Array-backed storage; safe under Swoole or as a pre-seeded read-only fixture under PCNTL (child writes are not shared).
 *
 * @internal built from InMemoryStorageConfig via ServerOptions::setStorageConfig()
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class InMemoryStorage implements EntryStorageInterface, ChangeJournalingInterface
{
    use ArrayEntryStorageTrait;
    use ChangeJournalingTrait;

    /**
     * @var array<string, Entry> keyed by normalised DN string
     */
    private array $entries = [];

    /**
     * @param Entry[] $entries pre-populated into the store
     */
    public function __construct(
        array $entries = [],
        ?ChangeJournalInterface $journal = null,
    ) {
        if ($journal !== null) {
            $this->useJournal($journal);
        }

        foreach ($entries as $entry) {
            $this->entries[$entry->getDn()->normalize()->toString()] = $entry;
        }
    }

    public function find(Dn $dn): ?Entry
    {
        return $this->entries[$dn->normalize()->toString()] ?? null;
    }

    public function exists(Dn $dn): bool
    {
        return isset($this->entries[$dn->normalize()->toString()]);
    }

    public function list(StorageListOptions $options): EntryStream
    {
        return $this->listFromArray(
            $options,
            $this->entries,
        );
    }

    public function store(Entry $entry): void
    {
        $this->entries[$entry->getDn()->normalize()->toString()] = $entry;
    }

    public function remove(Dn $dn): void
    {
        unset($this->entries[$dn->normalize()->toString()]);
    }

    public function atomic(callable $operation): void
    {
        $operation($this);
    }

    public function namingContexts(): array
    {
        return $this->namingContextsFromArray($this->entries);
    }

    protected function buildJournal(ChangeJournalConfig $config): ChangeJournalInterface
    {
        return new InMemoryChangeJournal($config->origin);
    }
}
