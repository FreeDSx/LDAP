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
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;
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
     * @param ?SubstringIndexInterface $substringIndex Shared by the translator, the index writer and schema setup.
     * @param ReplicaId $origin Stamped on the changes this server authors.
     * @param ?ChangeJournalConfig $journalConfig Attaches a journal on each connection when journaling is enabled.
     */
    public function __construct(
        private PdoConfig $config,
        private PdoDialectInterface $dialect,
        private FilterTranslatorInterface $translator,
        private AttributeContextInterface $attributeContext,
        private ?SubstringIndexInterface $substringIndex,
        private ReplicaId $origin,
        private SleeperInterface $sleeper,
        private ?ChangeJournalConfig $journalConfig,
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
        // Storage and its index writer share one statement pool, so both draw from the same connection and cache.
        $statements = new PdoStatementPool($provider);
        // The journal shares the transactor so an append joins the write transaction it belongs to.
        $transactor = new PdoTransactor(
            $provider,
            $this->dialect,
            $this->sleeper,
        );

        return new PdoStorage(
            $provider,
            $this->translator,
            $this->dialect,
            $this->attributeContext,
            $statements,
            new EntryIndexWriter(
                $this->dialect,
                $statements,
                $this->substringIndex,
            ),
            $transactor,
            $this->journalConfig === null ? null : AuditingChangeJournal::wrap(
                new PdoChangeJournal(
                    $transactor,
                    $this->dialect,
                    $statements,
                    $this->origin,
                ),
                $this->journalConfig,
            ),
        );
    }

    public function replicaStoreOn(PdoConnectionProviderInterface $provider): PdoReplicaPasswordStateStore
    {
        return new PdoReplicaPasswordStateStore(
            new PdoTransactor(
                $provider,
                $this->dialect,
                $this->sleeper,
            ),
            $this->dialect,
            new PdoStatementPool($provider),
        );
    }

    /**
     * PCNTL (shared) and Swoole-without-write-serialization (per-coroutine) run storage and the store on one provider.
     */
    private function assembleOnSingleProvider(PdoConnectionProviderInterface $provider): PdoBackend
    {
        return new PdoBackend(
            $this->storageOn($provider),
            $this->replicaStoreOn($provider),
        );
    }

    /**
     * Swoole with write serialization: reads run per-coroutine, writes funnel through one shared writer coroutine.
     */
    private function assembleSerializedSwoole(): PdoBackend
    {
        $reads = $this->coroutineProvider();
        $writes = $this->sharedProvider();
        // Each side journals on its own connection: the writer captures changes, the reader serves sync polls.
        $writeStorage = $this->storageOn($writes);
        $readStorage = $this->storageOn($reads);
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
                reads: $this->replicaStoreOn($reads),
                writes: $this->replicaStoreOn($writes),
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
