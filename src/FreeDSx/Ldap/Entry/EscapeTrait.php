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

namespace FreeDSx\Ldap\Entry;

use function bin2hex;
use function implode;
use function preg_replace_callback;
use function str_split;

/**
 * Some common methods around escaping attribute values and RDN values.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait EscapeTrait
{
    /**
     * Escape every character of a raw value.
     *
     * Note: This includes text that already looks escaped.
     *
     * @api
     */
    public static function escapeAll(string $value): string
    {
        if ($value === '') {
            return $value;
        }

        return '\\' . implode('\\', str_split(bin2hex($value), 2));
    }

    /**
     * Replace non-printable ASCII with escaped hex.
     */
    private static function escapeNonPrintable(string $value): string
    {
        return (string) preg_replace_callback('/([\x00-\x1F\x7F])/', function ($matches) {
            return '\\' . bin2hex($matches[1]);
        }, $value);
    }
}
