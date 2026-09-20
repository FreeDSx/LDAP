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
use FreeDSx\Ldap\Server\Backend\Storage\Capability\DrainableWritesInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\RowLockableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;

/**
 * Serializes writes through a single writer coroutine; reads run in place, on whichever connection the caller holds.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SerializedEntryWriter implements
    WriteEntryInterface,
    TransactionalWriteInterface,
    RowLockableInterface,
    DrainableWritesInterface
{
    public function __construct(
        private WriteEntryInterface&RowLockableInterface $writes,
        private TransactionalWriteInterface $transaction,
        private WriterQueueInterface $queue,
    ) {}

    public function drainWrites(): void
    {
        $this->queue->drain();
    }

    public function insert(Entry $entry): void
    {
        $this->submit(fn() => $this->writes->insert($entry));
    }

    public function store(
        Entry $entry,
        bool $rebuildIndexes = false,
    ): void {
        $this->submit(fn() => $this->writes->store(
            $entry,
            $rebuildIndexes,
        ));
    }

    public function renameSubtree(
        Dn $from,
        Dn $to,
    ): void {
        $this->submit(fn() => $this->writes->renameSubtree(
            $from,
            $to,
        ));
    }

    public function remove(Dn $dn): void
    {
        $this->submit(fn() => $this->writes->remove($dn));
    }

    public function removeAll(array $dns): void
    {
        $this->submit(fn() => $this->writes->removeAll($dns));
    }

    public function atomic(callable $operation): void
    {
        $this->submit(fn() => $this->transaction->atomic($operation));
    }

    /**
     * Only meaningful inside an atomic block, where the transaction holding the lock is open on the writer.
     */
    public function lockForWrite(Dn $dn): void
    {
        $this->writes->lockForWrite($dn);
    }

    /**
     * Only meaningful inside an atomic block.
     */
    public function lockForReference(Dn $dn): bool
    {
        return $this->writes->lockForReference($dn);
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
}
