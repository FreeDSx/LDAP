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
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryLister;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryReader;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\EntryWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\RowLockableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * PDO-backed storage; the container builds it from a PdoConfig set via ServerOptions::setStorageConfig().
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PdoStorage implements EntryStorageInterface, ResettableInterface, RowLockableInterface
{
    public function __construct(
        private PdoConnection $connection,
        private EntryReader $reader,
        private EntryLister $lister,
        private EntryWriter $writer,
    ) {}

    public function reset(): void
    {
        $this->connection->reset();
    }

    public function find(Dn $dn): ?Entry
    {
        return $this->reader->find($dn);
    }

    public function exists(Dn $dn): bool
    {
        return $this->reader->exists($dn);
    }

    public function hasChildren(Dn $dn): bool
    {
        return $this->reader->hasChildren($dn);
    }

    public function namingContexts(): array
    {
        return $this->reader->namingContexts();
    }

    public function list(StorageListOptions $options): EntryStream
    {
        return $this->lister->list($options);
    }

    public function insert(Entry $entry): void
    {
        $this->writer->insert($entry);
    }

    public function store(
        Entry $entry,
        bool $rebuildIndexes = false,
    ): void {
        $this->writer->store(
            $entry,
            $rebuildIndexes,
        );
    }

    public function renameSubtree(
        Dn $from,
        Dn $to,
    ): void {
        $this->writer->renameSubtree(
            $from,
            $to,
        );
    }

    public function remove(Dn $dn): void
    {
        $this->writer->remove($dn);
    }

    public function removeAll(array $dns): void
    {
        $this->writer->removeAll($dns);
    }

    public function atomic(callable $operation): void
    {
        $this->connection->atomic($operation);
    }

    public function lockForWrite(Dn $dn): void
    {
        $this->writer->lockForWrite($dn);
    }

    public function lockForReference(Dn $dn): bool
    {
        return $this->writer->lockForReference($dn);
    }
}
