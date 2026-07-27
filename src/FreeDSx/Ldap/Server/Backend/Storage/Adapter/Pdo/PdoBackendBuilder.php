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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use Closure;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\SwooleWriterQueue;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriteSerializingStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\SerializingReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;

/**
 * Assembles the PDO storage and its replica password-state store from a shared connection so both use one transactor.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PdoBackendBuilder
{
    private EntryStorageInterface $storage;

    private ReplicaPasswordStateStoreInterface $replicaPasswordStateStore;

    /**
     * @param SleeperInterface $sleeper Paces a retried transaction.
     * @param ?ChangeJournalConfig $journalConfig Attaches a change journal when journaling is enabled.
     */
    public function __construct(
        private readonly PdoConfig $config,
        RunnerMode $runner,
        private readonly SleeperInterface $sleeper = new BlockingSleeper(),
        private readonly ?ChangeJournalConfig $journalConfig = null,
    ) {
        if ($runner === RunnerMode::Swoole && $config->getSerializeSwooleWrites()) {
            $this->assembleSerializedSwoole();
        } else {
            $this->assembleOnSingleProvider($runner === RunnerMode::Swoole
                ? PdoStorageFactory::coroutineProvider($config)
                : PdoStorageFactory::sharedProvider($config));
        }
    }

    public function storage(): EntryStorageInterface
    {
        return $this->storage;
    }

    public function replicaPasswordStateStore(): ReplicaPasswordStateStoreInterface
    {
        return $this->replicaPasswordStateStore;
    }

    /**
     * PCNTL (shared) and Swoole-without-write-serialization (per-coroutine) run storage and the store on one provider.
     */
    private function assembleOnSingleProvider(PdoConnectionProviderInterface $provider): void
    {
        $this->storage = PdoStorageFactory::storageOn(
            $this->config,
            $provider,
            $this->sleeper,
            $this->journalConfig,
        );
        $this->replicaPasswordStateStore = $this->replicaStore($provider);
    }

    /**
     * Swoole with write serialization: reads run per-coroutine, writes funnel through one shared writer coroutine.
     */
    private function assembleSerializedSwoole(): void
    {
        $reads = PdoStorageFactory::coroutineProvider($this->config);
        $writes = PdoStorageFactory::sharedProvider($this->config);
        // Each side journals on its own connection: the writer captures changes, the reader serves sync polls.
        $writeStorage = PdoStorageFactory::storageOn(
            $this->config,
            $writes,
            $this->sleeper,
            $this->journalConfig,
        );
        $readStorage = PdoStorageFactory::storageOn(
            $this->config,
            $reads,
            $this->sleeper,
            $this->journalConfig,
        );
        $queue = new SwooleWriterQueue(
            batchWrapper: static fn(Closure $cb) => $writeStorage->atomic(static fn() => $cb()),
        );

        $this->storage = new WriteSerializingStorage(
            reads: $readStorage,
            writes: $writeStorage,
            queue: $queue,
        );
        $this->replicaPasswordStateStore = new SerializingReplicaPasswordStateStore(
            reads: $this->replicaStore($reads),
            writes: $this->replicaStore($writes),
            queue: $queue,
        );
    }

    private function replicaStore(PdoConnectionProviderInterface $provider): PdoReplicaPasswordStateStore
    {
        return new PdoReplicaPasswordStateStore(
            new PdoTransactor(
                $provider,
                $this->config->getDialect(),
                $this->sleeper,
            ),
            $this->config->getDialect(),
            new PdoStatementPool($provider),
        );
    }
}
