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

use FreeDSx\Ldap\Exception\InvalidArgumentException;
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
     * The bound-parameter markers for a statement whose width is only known at run time.
     *
     * @param string $marker A single value by default, or a parenthesised tuple for a multi-column row.
     */
    public static function markers(
        int $count,
        string $marker = '?',
    ): string {
        return implode(
            ', ',
            array_fill(
                0,
                $count,
                $marker,
            ),
        );
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

    /**
     * The least string above every string that starts with the prefix, under byte-wise ordering.
     *
     * @throws InvalidArgumentException when the prefix is empty or not UTF-8
     */
    public static function prefixUpperBound(string $prefix): string
    {
        $last = $prefix === ''
            ? null
            : ord($prefix[-1]);

        // UTF-8 never holds the byte 0xFF, so a valid prefix always leaves its last byte room to increment.
        if ($last === null || $last === 0xFF || !Text::isUtf8($prefix)) {
            throw new InvalidArgumentException('A prefix upper bound needs a non-empty UTF-8 prefix.');
        }

        return substr(
            $prefix,
            0,
            -1,
        ) . chr($last + 1);
    }

    /**
     * Whether a value spells an integer strictly between -$max and $max.
     */
    public static function isIntegerInside(
        string $value,
        string $max,
    ): bool {
        if (preg_match('/^-?(\d+)$/D', $value, $matches) !== 1) {
            return false;
        }
        $digits = ltrim(
            $matches[1],
            '0',
        );

        if (strlen($digits) !== strlen($max)) {
            return strlen($digits) < strlen($max);
        }

        return strcmp(
            $digits,
            $max,
        ) < 0;
    }

    /**
     * A prepared value cut to what the column holds; non-UTF-8 returns '', which matches binary-syntax rows only.
     */
    public static function truncate(string $value): string
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

    private static function prep(): StringPrep
    {
        return self::$prep ??= new StringPrep(foldCase: true);
    }
}
