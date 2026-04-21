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
     * Char limit for sidecar `value_lower`; queries longer than this can't match exactly.
     */
    public const MAX_INDEXED_VALUE_CHARS = 255;

    /**
     * Escape LIKE specials using `!` as the escape char.
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
     * True when $value is 7-bit ASCII.
     */
    public static function isAscii(string $value): bool
    {
        return preg_match(
            '/[\x80-\xff]/',
            $value
        ) !== 1;
    }
}
