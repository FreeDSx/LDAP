<?php

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
     * @var array
     */
    protected static $escapeMap = [
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
     *
     * @param null|string $value
     * @return string
     */
    protected static function encode(?string $value): string
    {
        return str_replace(
            array_keys(self::$escapeMap),
            array_values(self::$escapeMap),
            (string) $value
        );
    }

    /**
     * Percent-decode values from the URL.
     *
     * @param string $value
     * @return string
     */
    protected static function decode(string $value): string
    {
        return str_ireplace(
            array_values(self::$escapeMap),
            array_keys(self::$escapeMap),
            $value
        );
    }
}
