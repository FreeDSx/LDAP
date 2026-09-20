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

use Closure;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\CoroutinePdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnector;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\RoutingPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\EntryIndexWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\EntryWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryLinks;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryRowCodec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoSchema;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryLister;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryReader;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\PdoListQueryBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\MysqlFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqliteFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\Fts5SubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\NoSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\TrigramSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\ImmediateWriterQueue;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\SwooleWriterQueue;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriterQueueInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\SerializedEntryWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriteScope;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PdoChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PdoJournalGeneration;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeIndexForms;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoDriver;
use FreeDSx\Ldap\Server\Config\Storage\SubstringIndexMode;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\SerializingReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ServerOptions;

/**
 * Builds the PDO storage graph: one connection per server, with everything that reads or writes through it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PdoStorageContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            PdoDialectInterface::class => $this->makeDialect(...),
            SubstringIndexInterface::class => $this->makeSubstringIndex(...),
            FilterTranslatorInterface::class => $this->makeFilterTranslator(...),
            PdoSchema::class => $this->makeSchema(...),
            PdoConnector::class => $this->makeConnector(...),
            WriteScope::class => static fn(): WriteScope => new WriteScope(),
            PdoConnectionProviderInterface::class => $this->makeConnectionProvider(...),
            PdoConnection::class => $this->makeConnection(...),
            WriterQueueInterface::class => $this->makeWriterQueue(...),
            EntryIndexWriter::class => $this->makeEntryIndexWriter(...),
            EntryLinks::class => $this->makeEntryLinks(...),
            EntryRowCodec::class => static fn(): EntryRowCodec => new EntryRowCodec(),
            EntryReader::class => $this->makeReader(...),
            PdoListQueryBuilder::class => static fn(Container $container): PdoListQueryBuilder => new PdoListQueryBuilder(
                $container->get(PdoDialectInterface::class),
            ),
            EntryLister::class => $this->makeLister(...),
            EntryWriter::class => $this->makeWriter(...),
            PdoChangeJournal::class => $this->makeChangeJournal(...),
            SerializedEntryWriter::class => $this->makeSerializedEntryWriter(...),
            PdoReplicaPasswordStateStore::class => $this->makeReplicaPasswordStateStore(...),
            SerializingReplicaPasswordStateStore::class => $this->makeSerializingReplicaPasswordStateStore(...),
        ];
    }

    private function makeDialect(Container $container): PdoDialectInterface
    {
        return match ($this->requirePdoConfig($container)->getDriver()) {
            PdoDriver::Sqlite => new SqliteDialect(),
            PdoDriver::Mysql => new MysqlDialect(),
        };
    }

    /**
     * Auto resolves to the best index the driver supports, so a build without FTS5 still gets trigram narrowing.
     */
    private function makeSubstringIndex(Container $container): SubstringIndexInterface
    {
        $config = $this->requirePdoConfig($container);

        return match ($config->getSubstringIndexMode()) {
            SubstringIndexMode::None => new NoSubstringIndex(),
            SubstringIndexMode::Trigram => new TrigramSubstringIndex(),
            SubstringIndexMode::Auto => $config->getDriver() === PdoDriver::Sqlite
                && Fts5SubstringIndex::isSupported()
                    ? new Fts5SubstringIndex()
                    : new TrigramSubstringIndex(),
        };
    }

    private function makeFilterTranslator(Container $container): FilterTranslatorInterface
    {
        $attributeContext = $container->get(AttributeContextInterface::class);
        $indexForms = $container->get(AttributeIndexForms::class);
        $substringIndex = $container->get(SubstringIndexInterface::class);

        return match ($this->requirePdoConfig($container)->getDriver()) {
            PdoDriver::Sqlite => new SqliteFilterTranslator(
                $attributeContext,
                $indexForms,
                $substringIndex,
            ),
            PdoDriver::Mysql => new MysqlFilterTranslator(
                $attributeContext,
                $indexForms,
                $substringIndex,
            ),
        };
    }

    private function makeSchema(Container $container): PdoSchema
    {
        return new PdoSchema(
            $container->get(PdoDialectInterface::class),
            $container->get(SubstringIndexInterface::class),
        );
    }

    private function makeConnector(Container $container): PdoConnector
    {
        return new PdoConnector(
            $this->requirePdoConfig($container),
            $container->get(PdoSchema::class),
        );
    }

    /**
     * The serialized writer gets a connection of its own, opened only once a write actually reaches it.
     *
     * @throws RuntimeException when the Swoole runner is paired with a database private to one connection
     */
    private function makeConnectionProvider(Container $container): PdoConnectionProviderInterface
    {
        $isSwoole = $container->get(ServerOptions::class)->isRunnerMode(RunnerMode::Swoole);

        if ($isSwoole && !$this->requirePdoConfig($container)->isMultiProcessSafe()) {
            throw new RuntimeException(
                'The Swoole runner opens a connection per coroutine, so an in-memory SQLite database is not supported.',
            );
        }

        $connector = $container->get(PdoConnector::class);
        $initial = $connector->bootstrap();
        $open = $connector->open(...);
        $reads = $isSwoole
            ? new CoroutinePdoConnectionProvider($open)
            : new SharedPdoConnectionProvider(
                $initial,
                $open,
            );

        return new RoutingPdoConnectionProvider(
            $reads,
            new SharedPdoConnectionProvider(
                null,
                $open,
            ),
            $container->get(WriteScope::class),
        );
    }

    private function makeConnection(Container $container): PdoConnection
    {
        $provider = $container->get(PdoConnectionProviderInterface::class);

        return new PdoConnection(
            $provider,
            new PdoStatementPool($provider),
            new PdoTransactor(
                $provider,
                $container->get(PdoDialectInterface::class),
                $container->get(SleeperInterface::class),
            ),
        );
    }

    /**
     * Swoole funnels writes through one writer coroutine when configured to; every other setup writes in place.
     */
    private function makeWriterQueue(Container $container): WriterQueueInterface
    {
        $serializes = $container->get(ServerOptions::class)->isRunnerMode(RunnerMode::Swoole)
            && $this->requirePdoConfig($container)->getSerializeSwooleWrites();

        if (!$serializes) {
            return new ImmediateWriterQueue();
        }
        $connection = $container->get(PdoConnection::class);

        return new SwooleWriterQueue(
            batchWrapper: static fn(Closure $batch) => $connection->atomic(static fn() => $batch()),
            scope: $container->get(WriteScope::class),
        );
    }

    private function makeEntryIndexWriter(Container $container): EntryIndexWriter
    {
        return new EntryIndexWriter(
            $container->get(PdoDialectInterface::class),
            $container->get(PdoConnection::class),
            $container->get(AttributeIndexForms::class),
            $container->get(SubstringIndexInterface::class),
        );
    }

    private function makeEntryLinks(Container $container): EntryLinks
    {
        return new EntryLinks(
            $container->get(PdoDialectInterface::class),
            $container->get(PdoConnection::class),
            $container->get(LinkedAttributes::class),
        );
    }

    private function makeChangeJournal(Container $container): PdoChangeJournal
    {
        $dialect = $container->get(PdoDialectInterface::class);
        $connection = $container->get(PdoConnection::class);

        return new PdoChangeJournal(
            $connection,
            $dialect,
            new PdoJournalGeneration(
                $dialect,
                $connection,
            ),
            $container->get(ServerOptions::class)
                ->getReplicationConfig()
                ->getId(),
        );
    }

    private function makeReader(Container $container): EntryReader
    {
        return new EntryReader(
            $container->get(PdoConnection::class),
            $container->get(PdoDialectInterface::class),
            $container->get(EntryRowCodec::class),
            $container->get(EntryLinks::class),
        );
    }

    private function makeLister(Container $container): EntryLister
    {
        return new EntryLister(
            $container->get(PdoConnection::class),
            $container->get(PdoListQueryBuilder::class),
            $container->get(FilterTranslatorInterface::class),
            $container->get(AttributeContextInterface::class),
            $container->get(EntryRowCodec::class),
            $container->get(EntryLinks::class),
        );
    }

    /**
     * @throws RuntimeException when the mbstring extension, which renames slice DNs with, is not loaded
     */
    private function makeWriter(Container $container): EntryWriter
    {
        if (!extension_loaded('mbstring')) {
            throw new RuntimeException('The PDO storage backend requires the "mbstring" extension.');
        }

        return new EntryWriter(
            $container->get(PdoConnection::class),
            $container->get(PdoDialectInterface::class),
            $container->get(EntryReader::class),
            $container->get(EntryIndexWriter::class),
            $container->get(EntryRowCodec::class),
        );
    }

    private function makeSerializedEntryWriter(Container $container): SerializedEntryWriter
    {
        return new SerializedEntryWriter(
            $container->get(EntryWriter::class),
            $container->get(PdoConnection::class),
            $container->get(WriterQueueInterface::class),
        );
    }

    private function makeReplicaPasswordStateStore(Container $container): PdoReplicaPasswordStateStore
    {
        return new PdoReplicaPasswordStateStore(
            $container->get(PdoConnection::class),
            $container->get(PdoDialectInterface::class),
        );
    }

    private function makeSerializingReplicaPasswordStateStore(Container $container): SerializingReplicaPasswordStateStore
    {
        return new SerializingReplicaPasswordStateStore(
            $container->get(PdoReplicaPasswordStateStore::class),
            $container->get(WriterQueueInterface::class),
        );
    }

    private function requirePdoConfig(Container $container): PdoConfig
    {
        $config = $container->get(ServerOptions::class)->getStorageConfig();

        if (!$config instanceof PdoConfig) {
            throw new RuntimeException('The PDO storage backend requires a PdoConfig storage config.');
        }

        return $config;
    }
}
