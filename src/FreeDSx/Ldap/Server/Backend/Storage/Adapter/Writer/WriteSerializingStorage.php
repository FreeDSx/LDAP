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
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Routes reads to a per-coroutine read storage and serializes writes through a single writer coroutine.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WriteSerializingStorage implements EntryStorageInterface, ResettableInterface
{
    public function __construct(
        private EntryStorageInterface $reads,
        private EntryStorageInterface $writes,
        private WriterQueueInterface  $queue,
    ) {
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

    public function store(Entry $entry): void
    {
        $writes = $this->writes;
        $this->queue->run(static function () use ($writes, $entry): void {
            $writes->store($entry);
        });
    }

    public function remove(Dn $dn): void
    {
        $writes = $this->writes;
        $this->queue->run(static function () use ($writes, $dn): void {
            $writes->remove($dn);
        });
    }

    public function atomic(callable $operation): void
    {
        $writes = $this->writes;
        $this->queue->run(static function () use ($writes, $operation): void {
            $writes->atomic($operation);
        });
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
}
