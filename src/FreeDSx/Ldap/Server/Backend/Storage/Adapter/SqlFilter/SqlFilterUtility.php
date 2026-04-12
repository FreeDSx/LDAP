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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter;

/**
 * Shared utilities for SQL-based storage adapters.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SqlFilterUtility
{
    /**
     * Escapes LIKE special characters using `!` as the escape character.
     */
    public static function escape(string $value): string
    {
        return str_replace(
            ['!', '%', '_'],
            ['!!', '!%', '!_'],
            $value,
        );
    }

    /**
     * Returns true if the value contains only 7-bit ASCII bytes.
     *
     * The SQL translator's case-insensitive comparisons use `lower()`, which
     * is ASCII-only on SQLite and collation-dependent on MySQL.
     */
    public static function isAscii(string $value): bool
    {
        return preg_match(
            '/[\x80-\xff]/',
            $value
        ) !== 1;
    }
}
