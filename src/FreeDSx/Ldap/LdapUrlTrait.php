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

namespace FreeDSx\Ldap;

use function array_keys;
use function array_values;
use function str_ireplace;
use function str_replace;

/**
 * Some common methods for LDAP URLs and URL Extensions.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait LdapUrlTrait
{
    /**
     * @var array<string, string>
     */
    private static array $escapeMap = [
        '%' => '%25',
        '?' => '%3f',
        ' ' => '%20',
        '<' => '%3c',
        '>' => '%3e',
        '"' => '%22',
        '#' => '%23',
        '{' => '%7b',
        '}' => '%7d',
        '|' => '%7c',
        '\\' => '%5c',
        '^' => '%5e',
        '~' => '%7e',
        '[' => '%5b',
        ']' => '%5d',
        '`' => '%60',
    ];

    /**
     * Percent-encode certain values in the URL.
     */
    protected static function encode(?string $value): string
    {
        return str_replace(
            search: array_keys(self::$escapeMap),
            replace: array_values(self::$escapeMap),
            subject: (string) $value,
        );
    }

    /**
     * Percent-decode values from the URL.
     */
    protected static function decode(string $value): string
    {
        return str_ireplace(
            search: array_values(self::$escapeMap),
            replace: array_keys(self::$escapeMap),
            subject: $value,
        );
    }
}
