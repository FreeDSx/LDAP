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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqliteFilterTranslator;
use PDO;

/**
 * SQLite-specific factory for PdoStorage.
 *
 * Use the named constructors to select the appropriate runner:
 *
 *   SqliteStorage::forPcntl('/path/to/db.sqlite')
 *   SqliteStorage::forSwoole('/path/to/db.sqlite')
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SqliteStorage implements PdoStorageFactoryInterface
{
    use PdoStorageFactoryTrait;

    private const DB_CONNECTION_PREFIX = 'sqlite:';

    private const PRAGMA_JOURNAL_MODE_WAL = 'PRAGMA journal_mode = WAL';

    private const PRAGMA_SYNCHRONOUS_NORMAL = 'PRAGMA synchronous = NORMAL';

    public function __construct(private readonly string $dbPath)
    {
    }

    public static function forPcntl(string $dbPath): PdoStorage
    {
        return (new self($dbPath))->createShared();
    }

    public static function forSwoole(string $dbPath): PdoStorage
    {
        return (new self($dbPath))->createPerCoroutine();
    }

    protected function dialect(): PdoDialectInterface
    {
        return new SqliteDialect();
    }

    protected function translator(): FilterTranslatorInterface
    {
        return new SqliteFilterTranslator();
    }

    protected function openConnection(PdoDialectInterface $dialect): PDO
    {
        $pdo = new PDO(
            self::DB_CONNECTION_PREFIX . $this->dbPath,
            null,
            null,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
        );
        $pdo->exec(self::PRAGMA_JOURNAL_MODE_WAL);
        $pdo->exec(self::PRAGMA_SYNCHRONOUS_NORMAL);

        PdoStorage::initialize($pdo, $dialect);

        return $pdo;
    }
}
