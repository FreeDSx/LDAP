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

namespace FreeDSx\Ldap\Server\Config\Storage;

use PDO;

/**
 * The database engine a PdoConfig targets; the container derives the dialect and filter translator from it.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum PdoDriver
{
    case Sqlite;

    case Mysql;

    /**
     * The PDO driver extension the connection requires.
     */
    public function extension(): string
    {
        return match ($this) {
            self::Sqlite => 'pdo_sqlite',
            self::Mysql => 'pdo_mysql',
        };
    }

    /**
     * Whether the engine is better served by funnelling concurrent writes through a single connection.
     */
    public function serializesWrites(): bool
    {
        return match ($this) {
            self::Sqlite => true,
            self::Mysql => false,
        };
    }

    /**
     * @return array<int, mixed>
     */
    public function defaultPdoOptions(): array
    {
        return match ($this) {
            self::Sqlite => [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            self::Mysql => [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
            ],
        };
    }

    /**
     * Statements replayed on each new connection.
     *
     * @return list<string>
     */
    public function defaultSessionStatements(): array
    {
        return match ($this) {
            self::Sqlite => [
                'PRAGMA busy_timeout = 5000',
                'PRAGMA synchronous = NORMAL',
                'PRAGMA journal_mode = WAL',
                'PRAGMA foreign_keys = ON',
            ],
            // Strict mode is pinned: without it an overlong value is truncated and the write still reports success.
            self::Mysql => [
                'SET NAMES utf8mb4',
                "SET time_zone = '+00:00'",
                "SET SESSION sql_mode = CONCAT(@@SESSION.sql_mode, ',STRICT_TRANS_TABLES')",
            ],
        };
    }
}
