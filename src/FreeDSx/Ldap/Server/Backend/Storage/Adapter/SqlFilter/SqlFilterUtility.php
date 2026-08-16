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

use FreeDSx\Ldap\Schema\Matching\StringPrep;
use FreeDSx\Ldap\Schema\Text;

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

    private static ?StringPrep $prep = null;

    /**
     * The sidecar form of a value, for the write side and the query side alike.
     *
     * Both must prepare identically or SQL answers a question the evaluator would answer differently, so this is
     * the one definition of it.
     */
    public static function normalize(string $value): string
    {
        return self::truncate(self::prep()->prepareForEquality($value));
    }

    /**
     * The sidecar form of a substring fragment, which keeps its edge spaces where a whole value would not.
     */
    public static function normalizeFragment(string $fragment): string
    {
        return self::truncate(self::prep()->prepareFragment($fragment));
    }

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

    private static function prep(): StringPrep
    {
        return self::$prep ??= new StringPrep(foldCase: true);
    }

    /**
     * Non-UTF-8 returns '', which matches binary-syntax rows only.
     */
    private static function truncate(string $value): string
    {
        if (!Text::isUtf8($value)) {
            return '';
        }

        return mb_substr(
            $value,
            0,
            self::MAX_INDEXED_VALUE_CHARS,
            'UTF-8',
        );
    }
}
