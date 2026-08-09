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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\CoroutinePdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditingChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PdoChangeJournal;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use PDO;

/**
 * Low-level PDO connection and storage primitives; {@see PdoBackendBuilder} composes these plus the replica store.
 *
 * @internal the container builds storage from PdoConfig via ServerOptions::setStorageConfig()
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PdoStorageFactory
{
    /**
     * Storage without a journal, so it authors no changes an identity would be stamped on.
     */
    public static function forPcntl(PdoConfig $config): PdoStorage
    {
        return self::storageOn(
            $config,
            self::sharedProvider($config),
            new ReplicaId(),
        );
    }

    public static function sharedProvider(PdoConfig $config): SharedPdoConnectionProvider
    {
        $open = static fn(): PDO => self::open($config);

        return new SharedPdoConnectionProvider(
            $open(),
            $open,
        );
    }

    public static function coroutineProvider(PdoConfig $config): CoroutinePdoConnectionProvider
    {
        return new CoroutinePdoConnectionProvider(static fn(): PDO => self::open($config));
    }

    /**
     * @param ?ChangeJournalConfig $journalConfig Attaches a journal on this connection when journaling is enabled.
     * @param ReplicaId $origin Stamped on the changes this server authors.
     */
    public static function storageOn(
        PdoConfig $config,
        PdoConnectionProviderInterface $provider,
        ReplicaId $origin,
        ?SleeperInterface $sleeper = null,
        ?ChangeJournalConfig $journalConfig = null,
    ): PdoStorage {
        // Storage and its index writer share one statement pool, so both draw from the same connection and cache.
        $statements = new PdoStatementPool($provider);
        // The journal shares the transactor so an append joins the write transaction it belongs to.
        $transactor = new PdoTransactor(
            $provider,
            $config->getDialect(),
            $sleeper ?? new BlockingSleeper(),
        );

        return new PdoStorage(
            $provider,
            $config->getDialect()->createFilterTranslator($config->getSubstringIndex()),
            $config->getDialect(),
            $statements,
            new EntryIndexWriter(
                $config->getDialect(),
                $statements,
                $config->getSubstringIndex(),
            ),
            $transactor,
            $journalConfig === null ? null : AuditingChangeJournal::wrap(
                new PdoChangeJournal(
                    $transactor,
                    $config->getDialect(),
                    $statements,
                    $origin,
                ),
                $journalConfig,
            ),
        );
    }

    private static function open(PdoConfig $config): PDO
    {
        if (!extension_loaded($config->getDriverExtension())) {
            throw new RuntimeException(sprintf(
                'The "%s" extension is required for this PDO storage backend.',
                $config->getDriverExtension(),
            ));
        }

        $pdo = new PDO(
            $config->getDsn(),
            $config->getUsername(),
            $config->getPassword(),
            $config->getPdoOptions(),
        );

        foreach ($config->getSessionStatements() as $statement) {
            $pdo->exec($statement);
        }

        if ($config->getInitializeSchema()) {
            PdoStorage::initialize(
                $pdo,
                $config->getDialect(),
                $config->getSubstringIndex(),
            );
        }

        return $pdo;
    }
}
