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

namespace Tests\Support\FreeDSx\Ldap\Sync\Convergence;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\DeferredLinksInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\InMemoryReplicationCheckpoint;
use FreeDSx\Ldap\Sync\Consumer\ReplicaConsumer;
use FreeDSx\Ldap\Sync\Consumer\ReplicaMoves;
use FreeDSx\Ldap\Sync\Consumer\VerbatimStorageApplier;
use FreeDSx\Ldap\Sync\Provider\SyncCookie;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

/**
 * A replica's storage and checkpoint, which outlive the consumers a restart replaces.
 */
final class ConvergenceReplica
{
    public readonly RecordingLogger $logger;

    private InMemoryReplicationCheckpoint $checkpoint;

    private function __construct(
        private readonly ListEntryInterface $lister,
        private readonly ReadEntryInterface $reader,
        private readonly WriteEntryInterface $writer,
        private readonly TransactionalWriteInterface $transaction,
        private readonly DeferredLinksInterface $links,
    ) {
        $this->checkpoint = new InMemoryReplicationCheckpoint();
        $this->logger = new RecordingLogger();
    }

    public static function on(StorageConfigInterface $storage): self
    {
        $container = Container::forServer(new ServerOptions($storage));

        return new self(
            $container->get(ListEntryInterface::class),
            $container->get(ReadEntryInterface::class),
            $container->get(WriteEntryInterface::class),
            $container->get(TransactionalWriteInterface::class),
            $container->get(DeferredLinksInterface::class),
        );
    }

    /**
     * A consumer as a fresh process builds it, holding nothing from the last one but the storage and checkpoint.
     */
    public function consumer(): ReplicaConsumer
    {
        return new ReplicaConsumer(
            new VerbatimStorageApplier(
                $this->lister,
                $this->writer,
                $this->reader,
                $this->transaction,
                new ReplicaMoves(
                    $this->reader,
                    $this->lister,
                    $this->writer,
                ),
                $this->links,
            ),
            $this->checkpoint,
            $this->logger,
        );
    }

    /**
     * Loses the checkpoint, as a restart with the default in-memory checkpoint does.
     */
    public function forgetCheckpoint(): void
    {
        $this->checkpoint = new InMemoryReplicationCheckpoint();
    }

    /**
     * The sequence the checkpoint's cookie claims, or null when it holds none.
     */
    public function checkpointSeq(): ?int
    {
        $cookie = $this->checkpoint->read();

        return $cookie === null
            ? null
            : SyncCookie::decode($cookie)->seq;
    }

    public function snapshot(): DirectorySnapshot
    {
        return DirectorySnapshot::of($this->lister);
    }
}
