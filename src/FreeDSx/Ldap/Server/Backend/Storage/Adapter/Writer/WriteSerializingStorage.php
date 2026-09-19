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

use Closure;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\RowLockableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\DrainableWritesInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Serializes writes through a single writer coroutine; reads run in place, on whichever connection the caller holds.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WriteSerializingStorage implements
    EntryStorageInterface,
    ResettableInterface,
    DrainableWritesInterface,
    RowLockableInterface
{
    public function __construct(
        private EntryStorageInterface $storage,
        private WriterQueueInterface $queue,
    ) {}

    public function drainWrites(): void
    {
        $this->queue->drain();
    }

    public function find(
        Dn $dn,
        EntryProjection $projection = new EntryProjection(),
    ): ?Entry {
        return $this->storage->find(
            $dn,
            $projection,
        );
    }

    public function exists(Dn $dn): bool
    {
        return $this->storage->exists($dn);
    }

    public function hasChildren(Dn $dn): bool
    {
        return $this->storage->hasChildren($dn);
    }

    public function list(StorageListOptions $options): EntryStream
    {
        return $this->storage->list($options);
    }

    public function insert(Entry $entry): void
    {
        $this->submit(fn() => $this->storage->insert($entry));
    }

    public function store(
        Entry $entry,
        bool $rebuildIndexes = false,
    ): void {
        $this->submit(fn() => $this->storage->store(
            $entry,
            $rebuildIndexes,
        ));
    }

    public function renameSubtree(
        Dn $from,
        Dn $to,
    ): void {
        $this->submit(fn() => $this->storage->renameSubtree(
            $from,
            $to,
        ));
    }

    public function remove(Dn $dn): void
    {
        $this->submit(fn() => $this->storage->remove($dn));
    }

    public function removeAll(array $dns): void
    {
        $this->submit(fn() => $this->storage->removeAll($dns));
    }

    public function atomic(callable $operation): void
    {
        $this->submit(fn() => $this->storage->atomic($operation));
    }

    /**
     * Only meaningful inside an atomic block, where the transaction holding the lock is open on the writer.
     */
    public function lockForWrite(Dn $dn): void
    {
        $this->rowLockable()->lockForWrite($dn);
    }

    /**
     * Only meaningful inside an atomic block.
     */
    public function lockForReference(Dn $dn): bool
    {
        return $this->rowLockable()->lockForReference($dn);
    }

    public function namingContexts(): array
    {
        return $this->storage->namingContexts();
    }

    public function reset(): void
    {
        if ($this->storage instanceof ResettableInterface) {
            $this->storage->reset();
        }
    }

    /**
     * Runs directly when the writer is already executing, since submitting there would block the writer on itself.
     *
     * @param Closure(): void $write
     */
    private function submit(Closure $write): void
    {
        if ($this->queue->isWriter()) {
            $write();

            return;
        }

        $this->queue->run($write);
    }

    private function rowLockable(): RowLockableInterface
    {
        if (!$this->storage instanceof RowLockableInterface) {
            throw new InvalidArgumentException('The underlying storage does not support row locking.');
        }

        return $this->storage;
    }
}
