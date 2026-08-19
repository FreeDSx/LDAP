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

namespace FreeDSx\Ldap\Container\Provider;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\CoroutineLock;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\FileLock;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoBackendBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoStorageFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\MysqlFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqliteFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\Fts5SubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\TrigramSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditingChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\FileChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\JsonStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoDriver;
use FreeDSx\Ldap\Server\Config\Storage\SubstringIndexMode;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ServerOptions;
use Psr\Log\NullLogger;

/**
 * Builds the storage adapter selected by the StorageConfigInterface, plus the PDO primitives it is assembled from.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class StorageContainerProvider implements ContainerProviderInterface
{
    private const JOURNAL_SUFFIX = '.journal.jsonl';

    private const SEQ_SUFFIX = '.journal.seq';

    public function factories(): array
    {
        return [
            EntryStorageInterface::class => $this->makeStorage(...),
            PdoDialectInterface::class => $this->makePdoDialect(...),
            PdoStorageFactory::class => $this->makePdoStorageFactory(...),
            PdoBackendBuilder::class => $this->makePdoBackendBuilder(...),
        ];
    }

    /**
     * Build the runner-appropriate storage backend from the configured StorageConfigInterface.
     */
    private function makeStorage(Container $container): EntryStorageInterface
    {
        $config = $container->get(ServerOptions::class)->getStorageConfig();
        $journalConfig = $this->journalConfig($container);
        $origin = $this->journalOrigin($container);

        return match (true) {
            $config instanceof PdoConfig => $container->get(PdoBackendBuilder::class)->storage(),
            $config instanceof JsonStorageConfig => $this->makeJsonStorage(
                $container,
                $config,
                $journalConfig,
            ),
            $config instanceof InMemoryStorageConfig => new InMemoryStorage(
                $config->entries(),
                $journalConfig === null ? null : AuditingChangeJournal::wrap(
                    new InMemoryChangeJournal($origin),
                    $journalConfig,
                ),
            ),
            default => throw new RuntimeException(sprintf(
                'Unsupported storage config "%s".',
                $config::class,
            )),
        };
    }

    /**
     * The journal and storage share one lock, so a journal append re-enters the write it belongs to.
     */
    private function makeJsonStorage(
        Container $container,
        JsonStorageConfig $config,
        ?ChangeJournalConfig $journalConfig,
    ): JsonFileStorage {
        // Coroutines need a lock that yields rather than blocking the whole worker.
        $lock = $container->get(ServerOptions::class)->isRunnerMode(RunnerMode::Swoole)
            ? new CoroutineLock($config->path())
            : new FileLock($config->path());

        return new JsonFileStorage(
            $config->path(),
            $lock,
            $journalConfig === null ? null : AuditingChangeJournal::wrap(
                new FileChangeJournal(
                    $lock,
                    $config->path() . self::JOURNAL_SUFFIX,
                    $config->path() . self::SEQ_SUFFIX,
                    $this->journalOrigin($container),
                ),
                $journalConfig,
            ),
            $config->logger() ?? new NullLogger(),
        );
    }

    /**
     * The PDO backend assembly (storage + replica password-state store on one connection).
     */
    private function makePdoBackendBuilder(Container $container): PdoBackendBuilder
    {
        $options = $container->get(ServerOptions::class);

        return new PdoBackendBuilder(
            $container->get(PdoStorageFactory::class),
            $container->get(PdoDialectInterface::class),
            $container->get(SleeperInterface::class),
            $options->getRunnerConfig()->getMode(),
            $this->requirePdoConfig($container)->getSerializeSwooleWrites(),
        );
    }

    /**
     * The connection and storage primitives the PDO backend is assembled from.
     */
    private function makePdoStorageFactory(Container $container): PdoStorageFactory
    {
        $config = $this->requirePdoConfig($container);
        // One index instance is shared by the translator, the index writer and schema setup.
        $substringIndex = $this->makeSubstringIndex($config);

        return new PdoStorageFactory(
            $config,
            $container->get(PdoDialectInterface::class),
            $this->makePdoFilterTranslator($config, $substringIndex),
            $substringIndex,
            $this->journalOrigin($container),
            $container->get(SleeperInterface::class),
            $this->journalConfig($container),
        );
    }

    private function makePdoDialect(Container $container): PdoDialectInterface
    {
        return match ($this->requirePdoConfig($container)->getDriver()) {
            PdoDriver::Sqlite => new SqliteDialect(),
            PdoDriver::Mysql => new MysqlDialect(),
        };
    }

    private function makePdoFilterTranslator(
        PdoConfig $config,
        ?SubstringIndexInterface $substringIndex,
    ): FilterTranslatorInterface {
        return match ($config->getDriver()) {
            PdoDriver::Sqlite => new SqliteFilterTranslator($substringIndex),
            PdoDriver::Mysql => new MysqlFilterTranslator($substringIndex),
        };
    }

    /**
     * Auto resolves to the best index the driver supports, so a build without FTS5 still gets trigram narrowing.
     */
    private function makeSubstringIndex(PdoConfig $config): ?SubstringIndexInterface
    {
        return match ($config->getSubstringIndexMode()) {
            SubstringIndexMode::None => null,
            SubstringIndexMode::Trigram => new TrigramSubstringIndex(),
            SubstringIndexMode::Auto => $config->getDriver() === PdoDriver::Sqlite
                && Fts5SubstringIndex::isSupported()
                    ? new Fts5SubstringIndex()
                    : new TrigramSubstringIndex(),
        };
    }

    private function requirePdoConfig(Container $container): PdoConfig
    {
        $config = $container->get(ServerOptions::class)->getStorageConfig();

        if (!$config instanceof PdoConfig) {
            throw new RuntimeException('The PDO storage backend requires a PdoConfig storage config.');
        }

        return $config;
    }

    /**
     * The journal settings to build storage against, or null when nothing is recorded.
     */
    private function journalConfig(Container $container): ?ChangeJournalConfig
    {
        return $container->get(ServerOptions::class)
            ->getChangeJournalConfig();
    }

    /**
     * The identity stamped on changes this server authors.
     */
    private function journalOrigin(Container $container): ReplicaId
    {
        return $container->get(ServerOptions::class)
            ->getReplicationConfig()
            ->getId();
    }
}
