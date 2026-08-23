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

namespace FreeDSx\Ldap\Server\Utility;

use FreeDSx\Ldap\Exception\InvalidArgumentException;

use function bin2hex;
use function chr;
use function ctype_xdigit;
use function hex2bin;
use function implode;
use function ord;
use function random_bytes;
use function str_replace;
use function str_split;
use function strlen;
use function substr;
use function vsprintf;

/**
 * Generates RFC 4122 compliant UUIDs.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class Uuid
{
    private function __construct() {}

    /**
     * Generates a random UUID v4 string.
     */
    public static function v4(): string
    {
        $bytes = random_bytes(16);

        // Set version 4 and RFC 4122 variant bits.
        $bytes[6] = chr(ord($bytes[6]) & 0x0f | 0x40);
        $bytes[8] = chr(ord($bytes[8]) & 0x3f | 0x80);

        return vsprintf(
            '%s%s-%s-%s-%s-%s%s%s',
            str_split(
                bin2hex($bytes),
                4,
            ),
        );
    }

    /**
     * The dashed string form of a binary UUID, as RFC 4533 sync messages carry it on the wire.
     */
    public static function fromBinary(string $bytes): string
    {
        $hex = bin2hex($bytes);

        return implode('-', [
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20),
        ]);
    }

    /**
     * The 16-byte binary form of a dashed UUID string, as RFC 4533 sync controls carry it.
     *
     * @throws InvalidArgumentException when the value is not a UUID
     */
    public static function toBinary(string $uuid): string
    {
        $hex = str_replace('-', '', $uuid);

        // Validate before hex2bin so a malformed value returns cleanly rather than emitting a warning.
        $binary = strlen($hex) === 32 && ctype_xdigit($hex)
            ? hex2bin($hex)
            : false;

        if ($binary === false) {
            throw new InvalidArgumentException(sprintf('"%s" is not a valid UUID.', $uuid));
        }

        return $binary;
    }
}
