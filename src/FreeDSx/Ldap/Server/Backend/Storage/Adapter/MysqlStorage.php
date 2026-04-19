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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\MysqlFilterTranslator;
use PDO;

/**
 * MySQL/MariaDB factory for PdoStorage; use forPcntl()/forSwoole() to select the runner. Requires MySQL 8.0+ or MariaDB 10.6+.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MysqlStorage implements PdoStorageFactoryInterface
{
    use PdoStorageFactoryTrait;

    public function __construct(
        private readonly string $dsn,
        private readonly string $username,
        #[\SensitiveParameter]
        private readonly string $password,
    ) {
    }

    public static function forPcntl(
        string $dsn,
        string $username,
        #[\SensitiveParameter]
        string $password,
    ): PdoStorage {
        return (new self(
            $dsn,
            $username,
            $password,
        ))->createShared();
    }

    public static function forSwoole(
        string $dsn,
        string $username,
        #[\SensitiveParameter]
        string $password,
    ): PdoStorage {
        return (new self(
            $dsn,
            $username,
            $password,
        ))->createPerCoroutine();
    }

    protected function dialect(): PdoDialectInterface
    {
        return new MysqlDialect();
    }

    protected function translator(): FilterTranslatorInterface
    {
        return new MysqlFilterTranslator();
    }

    protected function openConnection(PdoDialectInterface $dialect): PDO
    {
        $pdo = new PDO(
            $this->dsn,
            $this->username,
            $this->password,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
            ],
        );
        $pdo->exec("SET NAMES utf8mb4");
        $pdo->exec("SET time_zone = '+00:00'");

        PdoStorage::initialize($pdo, $dialect);

        return $pdo;
    }
}
