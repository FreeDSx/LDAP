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

use function explode;
use function str_contains;
use function strlen;
use function strpos;
use function substr;

/**
 * Locates RFC 4514 separators that are not escaped, so every DN and RDN boundary is decided the same way.
 *
 * A separator counts only when preceded by an even number of backslashes, since a doubled backslash escapes
 * itself rather than the character that follows it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait UnescapedSeparatorTrait
{
    /**
     * @param non-empty-string $separator
     * @return string[]
     */
    private static function splitOnUnescaped(
        string $value,
        string $separator,
    ): array {
        // With nothing escaped every separator is real, which is both the common case and the cheap one.
        if (!str_contains($value, '\\')) {
            return explode(
                $separator,
                $value,
            );
        }

        $pieces = [];
        $start = 0;
        $offset = 0;

        while (($pos = strpos($value, $separator, $offset)) !== false) {
            if (self::isUnescapedAt($value, $pos)) {
                $pieces[] = substr($value, $start, $pos - $start);
                $start = $pos + strlen($separator);
            }

            $offset = $pos + strlen($separator);
        }

        $pieces[] = substr($value, $start);

        return $pieces;
    }

    /**
     * @param non-empty-string $separator
     */
    private static function hasUnescaped(
        string $value,
        string $separator,
    ): bool {
        if (!str_contains($value, '\\')) {
            return str_contains(
                $value,
                $separator,
            );
        }

        $offset = 0;

        while (($pos = strpos($value, $separator, $offset)) !== false) {
            if (self::isUnescapedAt($value, $pos)) {
                return true;
            }

            $offset = $pos + strlen($separator);
        }

        return false;
    }

    private static function isUnescapedAt(
        string $value,
        int $pos,
    ): bool {
        $slashes = 0;

        for ($i = $pos - 1; $i >= 0 && $value[$i] === '\\'; $i--) {
            $slashes++;
        }

        return $slashes % 2 === 0;
    }
}
