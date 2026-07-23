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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\SwooleWriterQueue;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriteSerializingStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use PDO;

/**
 * Builds a PdoStorage from a PdoConfig, selecting the runner: forPcntl() (shared) or forSwoole() (per-coroutine).
 *
 * @internal the container builds storage from PdoConfig via ServerOptions::setStorageConfig()
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PdoStorageFactory
{
    public static function forPcntl(PdoConfig $config): PdoStorage
    {
        return self::shared($config);
    }

    public static function forSwoole(PdoConfig $config): EntryStorageInterface
    {
        if (!$config->getSerializeSwooleWrites()) {
            return self::perCoroutine($config);
        }

        $writes = self::shared($config);

        return new WriteSerializingStorage(
            reads: self::perCoroutine($config),
            writes: $writes,
            queue: new SwooleWriterQueue(
                batchWrapper: static fn(Closure $cb) => $writes->atomic(static fn() => $cb()),
            ),
        );
    }

    private static function shared(PdoConfig $config): PdoStorage
    {
        $open = static fn(): PDO => self::open($config);

        return new PdoStorage(
            new SharedPdoConnectionProvider(
                $open(),
                $open,
            ),
            $config->getDialect()->createFilterTranslator($config->getSubstringIndex()),
            $config->getDialect(),
            $config->getSubstringIndex(),
        );
    }

    private static function perCoroutine(PdoConfig $config): PdoStorage
    {
        return new PdoStorage(
            new CoroutinePdoConnectionProvider(static fn(): PDO => self::open($config)),
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
