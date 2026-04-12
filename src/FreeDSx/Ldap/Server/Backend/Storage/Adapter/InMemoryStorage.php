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
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * An in-memory storage implementation backed by a plain PHP array.
 *
 * Suitable for single-process use cases: the Swoole server runner (all
 * connections share the same process memory), or pre-seeded read-only
 * use with the PCNTL runner (data seeded before run() is inherited by
 * all forked child processes).
 *
 * With the PCNTL runner, write operations performed by one child process
 * are not visible to other children or the parent.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class InMemoryStorage implements EntryStorageInterface
{
    use ArrayEntryStorageTrait;

    /**
     * Entries keyed by their normalised (lowercased) DN string.
     *
     * @var array<string, Entry>
     */
    private array $entries = [];

    /**
     * Pre-populate the storage with a set of entries.
     *
     * @param Entry[] $entries
     */
    public function __construct(array $entries = [])
    {
        foreach ($entries as $entry) {
            $this->entries[$entry->getDn()->normalize()->toString()] = $entry;
        }
    }

    public function find(Dn $dn): ?Entry
    {
        return $this->entries[$dn->toString()] ?? null;
    }

    public function exists(Dn $dn): bool
    {
        return isset($this->entries[$dn->toString()]);
    }

    public function list(StorageListOptions $options): EntryStream
    {
        return new EntryStream(
            $this->yieldByScope(
                $this->entries,
                $options->baseDn,
                $options->subtree,
                $options->timeLimit,
            ),
        );
    }

    public function store(Entry $entry): void
    {
        $this->entries[$entry->getDn()->normalize()->toString()] = $entry;
    }

    public function remove(Dn $dn): void
    {
        unset($this->entries[$dn->toString()]);
    }

    public function atomic(callable $operation): void
    {
        $operation($this);
    }
}
