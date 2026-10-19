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

namespace FreeDSx\Ldap\Schema;

/**
 * Helpers for the character-encoding checks LDAP syntaxes rely on (without needing the full ext-mb extension).
 */
final class Text
{
    private function __construct() {}

    /**
     * Whether the value contains only ASCII (IA5) bytes.
     */
    public static function isAscii(string $value): bool
    {
        return preg_match('/[^\x00-\x7F]/', $value) === 0;
    }

    /**
     * Whether the value contains only printable ASCII bytes, without control characters.
     */
    public static function isPrintableAscii(string $value): bool
    {
        return preg_match('/[^\x20-\x7E]/', $value) === 0;
    }

    /**
     * Whether the value is well-formed UTF-8.
     */
    public static function isUtf8(string $value): bool
    {
        return preg_match('//u', $value) === 1;
    }

    /**
     * Counts UTF-8 code points; continuation bytes (0x80-0xBF) are not counted.
     */
    public static function lengthOf(string $value): int
    {
        return (int) preg_match_all('/[^\x80-\xBF]/', $value);
    }
}
