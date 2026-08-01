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

namespace FreeDSx\Ldap\Schema\Definition;

/**
 * Shared string-formatting helpers for schema definition value objects that produce RFC 4512 description strings.
 */
trait DefinitionStringTrait
{
    /**
     * Returns "KEYWORD value" when value is non-null, otherwise null (for use with array_filter).
     */
    private function token(
        string $keyword,
        ?string $value,
    ): ?string {
        return $value !== null
            ? $keyword . ' ' . $value
            : null;
    }

    /**
     * Returns the keyword string when $include is true, otherwise null (for use with array_filter).
     */
    private function flag(
        string $keyword,
        bool $include,
    ): ?string {
        return $include
            ? $keyword
            : null;
    }

    /**
     * Returns a single-quoted, backslash-escaped value suitable for DESC fields.
     */
    private function quoteString(string $value): string
    {
        return "'" . addcslashes($value, "'\\") . "'";
    }

    /**
     * Formats one or more quoted descriptor strings per RFC 4512 §1.4, which separates them by space.
     *
     * @param list<string> $values
     */
    private function formatDescriptors(array $values): string
    {
        if (count($values) === 1) {
            return "'" . addcslashes($values[0], "'\\") . "'";
        }

        $quoted = array_map(
            fn(string $v) => "'" . addcslashes($v, "'\\") . "'",
            $values,
        );

        return '( ' . implode(' ', $quoted) . ' )';
    }

    /**
     * Formats one or more OIDs per RFC 4512 §1.4, which separates them by a dollar sign.
     *
     * @param list<string> $oids
     */
    private function formatOids(array $oids): string
    {
        if (count($oids) === 1) {
            return $oids[0];
        }

        return '( ' . implode(' $ ', $oids) . ' )';
    }
}
