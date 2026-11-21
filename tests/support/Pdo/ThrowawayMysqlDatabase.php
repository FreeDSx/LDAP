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

namespace Tests\Support\FreeDSx\Ldap\Pdo;

use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use PDO;
use PDOException;

use function bin2hex;
use function extension_loaded;
use function getenv;
use function preg_replace;
use function random_bytes;
use function rtrim;

/**
 * A database of its own on the MySQL server that MYSQL_DSN names, for a test that must not share one.
 */
final class ThrowawayMysqlDatabase
{
    private function __construct(
        private readonly PDO $server,
        private readonly string $name,
        private readonly string $dsn,
        private readonly string $user,
        private readonly string $password,
    ) {}

    /**
     * Creates the database, or answers null when MYSQL_DSN names no reachable server.
     */
    public static function create(): ?self
    {
        $dsn = getenv('MYSQL_DSN');

        if (!extension_loaded('pdo_mysql') || $dsn === false || $dsn === '') {
            return null;
        }
        $user = getenv('MYSQL_USER') ?: 'root';
        $password = getenv('MYSQL_PASSWORD') ?: 'root';
        $serverDsn = self::withoutDatabase($dsn);

        try {
            $server = new PDO(
                $serverDsn,
                $user,
                $password,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_TIMEOUT => 2,
                ],
            );
        } catch (PDOException) {
            return null;
        }
        $name = 'freedsx_' . bin2hex(random_bytes(6));
        $server->exec("CREATE DATABASE `{$name}`");

        return new self(
            $server,
            $name,
            "{$serverDsn};dbname={$name}",
            $user,
            $password,
        );
    }

    public function config(): PdoConfig
    {
        return PdoConfig::forMysql(
            $this->dsn,
            $this->user,
            $this->password,
        );
    }

    public function drop(): void
    {
        $this->server->exec("DROP DATABASE IF EXISTS `{$this->name}`");
    }

    /**
     * The DSN with no default database, which keeps the connection apart from whatever another test does to that one.
     */
    private static function withoutDatabase(string $dsn): string
    {
        return rtrim(
            (string) preg_replace(
                '/(?<=[:;])dbname=[^;]*;?/',
                '',
                $dsn,
            ),
            ';',
        );
    }
}
