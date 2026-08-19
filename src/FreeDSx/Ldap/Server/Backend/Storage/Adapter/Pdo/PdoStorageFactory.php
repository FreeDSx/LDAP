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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\CoroutinePdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditingChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PdoChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use PDO;

/**
 * Low-level PDO connection and storage primitives; {@see PdoBackendBuilder} composes these plus the replica store.
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
     * Storage over a single connection shared by every forked child.
     */
    public function sharedStorage(): PdoStorage
    {
        return $this->storageOn($this->sharedProvider());
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
