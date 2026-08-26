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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\EntryIndexReindexer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoBackend;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoStorageFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\SortKeyComparator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\MysqlFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqliteFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\Fts5SubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\TrigramSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditingChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContext;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeIndexForms;
use FreeDSx\Ldap\Server\Backend\Storage\Search\StorageListOptionsFactory;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoDriver;
use FreeDSx\Ldap\Server\Config\Storage\SubstringIndexMode;
use FreeDSx\Ldap\ServerOptions;

/**
 * Builds the storage adapter selected by the StorageConfigInterface, plus the PDO primitives it is assembled from.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class StorageContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            AttributeContextInterface::class => $this->makeAttributeContext(...),
            AttributeIndexForms::class => $this->makeAttributeIndexForms(...),
            SortKeyComparator::class => $this->makeSortKeyComparator(...),
            StorageListOptionsFactory::class => $this->makeStorageListOptionsFactory(...),
            EntryStorageInterface::class => $this->makeStorage(...),
            EntryIndexReindexer::class => $this->makeEntryIndexReindexer(...),
            PdoDialectInterface::class => $this->makePdoDialect(...),
            PdoStorageFactory::class => $this->makePdoStorageFactory(...),
            PdoBackend::class => $this->makePdoBackend(...),
        ];
    }

    private function makeEntryIndexReindexer(Container $container): EntryIndexReindexer
    {
        return new EntryIndexReindexer($container->get(EntryStorageInterface::class));
    }

    /**
     * The schema derived answers the filter translators and the sort-spec builder need about an attribute.
     */
    private function makeAttributeContext(Container $container): AttributeContextInterface
    {
        $schema = $container->get(ServerOptions::class)->getSchema();

        return new AttributeContext(
            $schema,
            new AttributeSyntaxResolver($schema),
        );
    }

    /**
     * The index forms a store must key values by for its index to answer the rule the evaluator applies.
     */
    private function makeAttributeIndexForms(Container $container): AttributeIndexForms
    {
        $schema = $container->get(ServerOptions::class)->getSchema();

        return new AttributeIndexForms(
            $schema,
            $container->get(EqualityComparatorResolver::class),
        );
    }

    private function makeSortKeyComparator(Container $container): SortKeyComparator
    {
        return new SortKeyComparator($container->get(ServerOptions::class)->getSchema());
    }

    private function makeStorageListOptionsFactory(Container $container): StorageListOptionsFactory
    {
        $options = $container->get(ServerOptions::class);

        return new StorageListOptionsFactory(
            $options->getSchema(),
            $options->makeSearchLimits(),
        );
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
            $config instanceof PdoConfig => $container->get(PdoBackend::class)->storage,
            $config instanceof InMemoryStorageConfig => new InMemoryStorage(
                $config->entries(),
                $journalConfig === null ? null : AuditingChangeJournal::wrap(
                    new InMemoryChangeJournal($origin),
                    $journalConfig,
                ),
                $container->get(SortKeyComparator::class),
            ),
            default => throw new RuntimeException(sprintf(
                'Unsupported storage config "%s".',
                $config::class,
            )),
        };
    }

    /**
     * The PDO backend assembly (storage + replica password-state store on shared connections).
     */
    private function makePdoBackend(Container $container): PdoBackend
    {
        $options = $container->get(ServerOptions::class);

        return $container->get(PdoStorageFactory::class)->assemble(
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
            $this->makePdoFilterTranslator(
                $config,
                $container->get(AttributeContextInterface::class),
                $container->get(AttributeIndexForms::class),
                $substringIndex,
            ),
            $container->get(AttributeContextInterface::class),
            $container->get(AttributeIndexForms::class),
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
        AttributeContextInterface $attributeContext,
        AttributeIndexForms $indexForms,
        ?SubstringIndexInterface $substringIndex,
    ): FilterTranslatorInterface {
        return match ($config->getDriver()) {
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
