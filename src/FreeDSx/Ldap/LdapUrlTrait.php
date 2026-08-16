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

use function bin2hex;
use function hex2bin;
use function preg_replace_callback;

/**
 * Some common methods for LDAP URLs and URL Extensions.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait LdapUrlTrait
{
    /**
     * Anything outside printable ASCII, plus the printable characters that would otherwise read as structure.
     */
    private const MUST_ENCODE = '/[^\x21-\x7E]|[%?<>"#{}|\\\\^~\[\]`]/';

    /**
     * Percent-encode the octets a generated URL may not carry (RFC 4516 2.1).
     */
    protected static function encode(?string $value): string
    {
        return (string) preg_replace_callback(
            pattern: self::MUST_ENCODE,
            callback: static fn(array $matches): string => '%' . bin2hex($matches[0]),
            subject: (string) $value,
        );
    }

    /**
     * Percent-decode in a single pass, so an encoded percent yields text rather than decoding a second time.
     */
    protected static function decode(string $value): string
    {
        return (string) preg_replace_callback(
            pattern: '/%([0-9A-Fa-f]{2})/',
            callback: static fn(array $matches): string => (string) hex2bin($matches[1]),
            subject: $value,
        );
    }
}
