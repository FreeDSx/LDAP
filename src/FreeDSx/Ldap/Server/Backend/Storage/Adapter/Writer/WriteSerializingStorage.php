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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\DrainableWritesInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Routes reads to a per-coroutine read storage and serializes writes through a single writer coroutine.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WriteSerializingStorage implements
    EntryStorageInterface,
    ResettableInterface,
    ChangeJournalingInterface,
    DrainableWritesInterface
{
    public function __construct(
        private EntryStorageInterface $reads,
        private EntryStorageInterface $writes,
        private WriterQueueInterface $queue,
    ) {}

    public function drainWrites(): void
    {
        $this->queue->drain();
    }

    public function find(Dn $dn): ?Entry
    {
        return $this->reads->find($dn);
    }

    public function exists(Dn $dn): bool
    {
        return $this->reads->exists($dn);
    }

    public function hasChildren(Dn $dn): bool
    {
        return $this->reads->hasChildren($dn);
    }

    public function list(StorageListOptions $options): EntryStream
    {
        return $this->reads->list($options);
    }

    public function store(
        Entry $entry,
        bool $rebuildIndexes = false,
    ): void {
        $this->queue->run(fn() => $this->writes->store(
            $entry,
            $rebuildIndexes,
        ));
    }

    public function renameSubtree(
        Dn $from,
        Dn $to,
    ): void {
        $this->queue->run(fn() => $this->writes->renameSubtree(
            $from,
            $to,
        ));
    }

    public function remove(Dn $dn): void
    {
        $this->queue->run(fn() => $this->writes->remove($dn));
    }

    public function removeAll(array $dns): void
    {
        $this->queue->run(fn() => $this->writes->removeAll($dns));
    }

    public function atomic(callable $operation): void
    {
        $this->queue->run(fn() => $this->writes->atomic($operation));
    }

    public function namingContexts(): array
    {
        return $this->reads->namingContexts();
    }

    public function reset(): void
    {
        if ($this->reads instanceof ResettableInterface) {
            $this->reads->reset();
        }

        if ($this->writes instanceof ResettableInterface) {
            $this->writes->reset();
        }
    }

    /**
     * Defensive delegate.
     *
     * The journal appends actually run on the write storage.
     */
    public function appendChange(PendingChange $change): void
    {
        $this->journaling($this->writes)->appendChange($change);
    }

    /**
     * Reads through the per-coroutine storage so sync polls never contend with the serialized writer.
     */
    public function changeJournal(): ?ChangeJournalInterface
    {
        return $this->journaling($this->reads)->changeJournal();
    }

    private function journaling(EntryStorageInterface $storage): ChangeJournalingInterface
    {
        if (!$storage instanceof ChangeJournalingInterface) {
            throw new InvalidArgumentException('The underlying storage does not support change journaling.');
        }

        return $storage;
    }
}
