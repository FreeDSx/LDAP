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
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\CoroutinePdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\SwooleWriterQueue;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriteSerializingStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditingChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PdoChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PdoJournalGeneration;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeIndexForms;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\SerializingReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use PDO;

/**
 * Builds the PDO connections and the storage, journal and replica store that run on them.
 *
 * @internal the container builds storage from PdoConfig via ServerOptions::setStorageConfig()
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PdoStorageFactory
{
    /**
     * @param ReplicaId $origin Stamped on the changes this server authors.
     * @param ?ChangeJournalConfig $journalConfig Attaches a journal on each connection when journaling is enabled.
     */
    public function __construct(
        private PdoConfig $config,
        private PdoDialectInterface $dialect,
        private FilterTranslatorInterface $translator,
        private AttributeContextInterface $attributeContext,
        private AttributeIndexForms $indexForms,
        private SubstringIndexInterface $substringIndex,
        private ReplicaId $origin,
        private SleeperInterface $sleeper,
        private ?ChangeJournalConfig $journalConfig,
        private ?LinkedAttributes $linked = null,
    ) {}

    public function sharedProvider(): SharedPdoConnectionProvider
    {
        $open = fn(): PDO => $this->open();

        return new SharedPdoConnectionProvider(
            $open(),
            $open,
        );
    }

    public function coroutineProvider(): CoroutinePdoConnectionProvider
    {
        return new CoroutinePdoConnectionProvider(fn(): PDO => $this->open());
    }

    /**
     * The storage and replica password-state store for a runner, sharing the connections they are assembled on.
     *
     * @param bool $serializeWrites Funnels writes through one connection, honoured only under the Swoole runner.
     */
    public function assemble(
        RunnerMode $runner,
        bool $serializeWrites,
    ): PdoBackend {
        if ($runner === RunnerMode::Swoole && $serializeWrites) {
            return $this->assembleSerializedSwoole();
        }

        return $this->assembleOnSingleProvider($runner === RunnerMode::Swoole
            ? $this->coroutineProvider()
            : $this->sharedProvider());
    }

    public function storageOn(PdoConnectionProviderInterface $provider): PdoStorage
    {
        return $this->storageWith($this->connectionOn($provider));
    }

    /**
     * Everything on one connection shares its statement pool and transactor, so a journal append joins the write.
     */
    private function connectionOn(PdoConnectionProviderInterface $provider): PdoConnection
    {
        return new PdoConnection(
            $provider,
            new PdoStatementPool($provider),
            new PdoTransactor(
                $provider,
                $this->dialect,
                $this->sleeper,
            ),
        );
    }

    private function storageWith(PdoConnection $connection): PdoStorage
    {
        return new PdoStorage(
            $connection,
            $this->translator,
            $this->dialect,
            $this->attributeContext,
            new EntryIndexWriter(
                $this->dialect,
                $connection,
                $this->indexForms,
                $this->substringIndex,
            ),
            $this->journalConfig === null ? null : AuditingChangeJournal::wrap(
                new PdoChangeJournal(
                    $connection,
                    $this->dialect,
                    new PdoJournalGeneration(
                        $this->dialect,
                        $connection,
                    ),
                    $this->origin,
                ),
                $this->journalConfig,
            ),
            $this->linked === null ? null : new EntryLinks(
                $this->dialect,
                $connection,
                $this->linked,
            ),
        );
    }

    private function replicaStoreWith(PdoConnection $connection): PdoReplicaPasswordStateStore
    {
        return new PdoReplicaPasswordStateStore(
            $connection,
            $this->dialect,
        );
    }

    /**
     * PCNTL (shared) and Swoole-without-write-serialization (per-coroutine) run storage and the store on one provider.
     */
    private function assembleOnSingleProvider(PdoConnectionProviderInterface $provider): PdoBackend
    {
        $connection = $this->connectionOn($provider);

        return new PdoBackend(
            $this->storageWith($connection),
            $this->replicaStoreWith($connection),
        );
    }

    /**
     * Swoole with write serialization: reads run per-coroutine, writes funnel through one shared writer coroutine.
     */
    private function assembleSerializedSwoole(): PdoBackend
    {
        $reads = $this->connectionOn($this->coroutineProvider());
        $writes = $this->connectionOn($this->sharedProvider());
        // Each side journals on its own connection: the writer captures changes, the reader serves sync polls.
        $writeStorage = $this->storageWith($writes);
        $readStorage = $this->storageWith($reads);
        $queue = new SwooleWriterQueue(
            batchWrapper: static fn(Closure $cb) => $writeStorage->atomic(static fn() => $cb()),
        );

        return new PdoBackend(
            new WriteSerializingStorage(
                reads: $readStorage,
                writes: $writeStorage,
                queue: $queue,
            ),
            new SerializingReplicaPasswordStateStore(
                reads: $this->replicaStoreWith($reads),
                writes: $this->replicaStoreWith($writes),
                queue: $queue,
            ),
        );
    }

    private function open(): PDO
    {
        $extension = $this->config->getDriver()->extension();

        if (!extension_loaded($extension)) {
            throw new RuntimeException(sprintf(
                'The "%s" extension is required for this PDO storage backend.',
                $extension,
            ));
        }

        $pdo = new PDO(
            $this->config->getDsn(),
            $this->config->getUsername(),
            $this->config->getPassword(),
            $this->config->getPdoOptions(),
        );

        foreach ($this->config->getSessionStatements() as $statement) {
            $pdo->exec($statement);
        }

        if ($this->config->getInitializeSchema()) {
            PdoStorage::initialize(
                $pdo,
                $this->dialect,
                $this->substringIndex,
            );
        }

        return $pdo;
    }
}
