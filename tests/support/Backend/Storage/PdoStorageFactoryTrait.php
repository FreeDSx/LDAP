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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoStorageFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\MysqlFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqliteFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\Fts5SubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\TrigramSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
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
    ): PdoStorageFactory {
        $substringIndex ??= self::makeSubstringIndex($config);

        return new PdoStorageFactory(
            $config,
            self::makePdoDialect($config->getDriver()),
            self::makePdoFilterTranslator($config->getDriver(), $substringIndex),
            $substringIndex,
            new ReplicaId(),
            new BlockingSleeper(),
            $journalConfig,
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
        ?SubstringIndexInterface $substringIndex = null,
    ): FilterTranslatorInterface {
        return match ($driver) {
            PdoDriver::Sqlite => new SqliteFilterTranslator($substringIndex),
            PdoDriver::Mysql => new MysqlFilterTranslator($substringIndex),
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
