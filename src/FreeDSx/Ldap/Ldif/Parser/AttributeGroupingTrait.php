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

namespace FreeDSx\Ldap\Ldif\Parser;

use function strtolower;

/**
 * Shared by the record parsers, which each read attribute directives and must group them the same way.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait AttributeGroupingTrait
{
    /**
     * Groups by attribute description, which RFC 4512 2.5 makes case insensitive.
     *
     * @param list<LdifDirective> $directives
     * @return array<string, list<string>>
     */
    private function groupAttributeValues(array $directives): array
    {
        $attributes = [];
        $spellings = [];

        // Keyed by folded description, so every later spelling collects under the one the record used first.
        foreach ($directives as $directive) {
            $spelling = $spellings[strtolower($directive->name)] ??= $directive->name;
            $attributes[$spelling][] = $directive->value;
        }

        return $attributes;
    }
}
