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

namespace Tests\Support\FreeDSx\Ldap\Backend\Storage;

use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoEntryDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryIndexWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoStorageFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\MysqlFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqliteFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\Fts5SubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\TrigramSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContext;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeIndexForms;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoDriver;
use FreeDSx\Ldap\Server\Config\Storage\SubstringIndexMode;

/**
 * Mirrors the container's PDO wiring, so tests needing real storage do not each rebuild the dialect and translator.
 */
trait PdoStorageFactoryTrait
{
    /**
     * @param ?SubstringIndexInterface $substringIndex Overrides the config's mode where a test pins one index.
     */
    private static function makePdoStorageFactory(
        PdoConfig $config,
        ?ChangeJournalConfig $journalConfig = null,
        ?SubstringIndexInterface $substringIndex = null,
        ?AttributeContextInterface $attributeContext = null,
        ?AttributeIndexForms $indexForms = null,
    ): PdoStorageFactory {
        $substringIndex ??= self::makeSubstringIndex($config);
        $attributeContext ??= self::makeAttributeContext();
        $indexForms ??= self::makeAttributeIndexForms();

        return new PdoStorageFactory(
            $config,
            self::makePdoDialect($config->getDriver()),
            self::makePdoFilterTranslator(
                $config->getDriver(),
                $attributeContext,
                $indexForms,
                $substringIndex,
            ),
            $attributeContext,
            $indexForms,
            $substringIndex,
            new ReplicaId(),
            new BlockingSleeper(),
            $journalConfig,
        );
    }

    /**
     * Storage that opens its own shared connection, as the PCNTL path does.
     */
    private static function makeSharedPdoStorage(
        PdoConfig $config,
        ?ChangeJournalConfig $journalConfig = null,
    ): PdoStorage {
        $factory = self::makePdoStorageFactory(
            $config,
            $journalConfig,
        );

        return $factory->storageOn($factory->sharedProvider());
    }

    /**
     * Storage over an already-open connection, wired the way the container wires it.
     *
     * The config only feeds connection opening, which the supplied provider has already done, so it is inert here.
     */
    private static function makePdoStorage(
        PdoConnectionProviderInterface $provider,
        ?SubstringIndexInterface $substringIndex = null,
    ): PdoStorage {
        return self::makePdoStorageFactory(
            PdoConfig::forSqlite(':memory:'),
            substringIndex: $substringIndex,
        )->storageOn($provider);
    }

    /**
     * @param ?Schema $schema Defaults to core, matching what a server is configured with unless a test says otherwise.
     */
    private static function makeAttributeContext(?Schema $schema = null): AttributeContextInterface
    {
        $schema ??= SchemaResource::Core->load();

        return new AttributeContext(
            $schema,
            new AttributeSyntaxResolver($schema),
        );
    }

    /**
     * @param ?Schema $schema Defaults to core, matching what a server is configured with unless a test says otherwise.
     */
    private static function makeAttributeIndexForms(?Schema $schema = null): AttributeIndexForms
    {
        $schema ??= SchemaResource::Core->load();

        return new AttributeIndexForms(
            $schema,
            new EqualityComparatorResolver($schema),
        );
    }

    /**
     * The index writer paired with a storage's own statement pool, for tests constructing PdoStorage directly.
     */
    private static function makeEntryIndexWriter(
        PdoEntryDialectInterface $dialect,
        PdoStatementPool $statements,
        ?SubstringIndexInterface $substringIndex = null,
    ): EntryIndexWriter {
        return new EntryIndexWriter(
            $dialect,
            $statements,
            self::makeAttributeIndexForms(),
            $substringIndex,
        );
    }

    private static function makePdoDialect(PdoDriver $driver): PdoDialectInterface
    {
        return match ($driver) {
            PdoDriver::Sqlite => new SqliteDialect(),
            PdoDriver::Mysql => new MysqlDialect(),
        };
    }

    private static function makePdoFilterTranslator(
        PdoDriver $driver,
        AttributeContextInterface $attributeContext,
        AttributeIndexForms $indexForms,
        ?SubstringIndexInterface $substringIndex = null,
    ): FilterTranslatorInterface {
        return match ($driver) {
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

    private static function makeSubstringIndex(PdoConfig $config): ?SubstringIndexInterface
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
}
