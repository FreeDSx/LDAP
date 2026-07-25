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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
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
    public static function forPcntl(PdoConfig $config): PdoStorage
    {
        return self::storageOn(
            $config,
            self::sharedProvider($config),
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

    public static function storageOn(
        PdoConfig $config,
        PdoConnectionProviderInterface $provider,
    ): PdoStorage {
        return new PdoStorage(
            $provider,
            $config->getDialect()->createFilterTranslator($config->getSubstringIndex()),
            $config->getDialect(),
            $config->getSubstringIndex(),
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
