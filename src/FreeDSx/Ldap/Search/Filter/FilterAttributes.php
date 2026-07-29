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

namespace FreeDSx\Ldap\Search\Filter;

use FreeDSx\Ldap\Entry\Attribute;

use function array_merge;
use function array_unique;
use function array_values;

/**
 * Collects the base attribute names a filter references, so a reader can materialize just those for evaluation.
 */
final class FilterAttributes
{
    /**
     * Lowercased base attribute names the filter references, or null when the set is indeterminate (an extensibleMatch
     * without an attribute, or an unrecognized filter type) and every attribute must therefore be materialized.
     *
     * @return list<string>|null
     */
    public static function referenced(FilterInterface $filter): ?array
    {
        $names = self::walk($filter);

        if ($names === null) {
            return null;
        }

        return array_values(array_unique($names));
    }

    /**
     * @return list<string>|null
     */
    private static function walk(FilterInterface $filter): ?array
    {
        if ($filter instanceof FilterContainerInterface) {
            return self::walkChildren($filter->get());
        }

        if ($filter instanceof NotFilter) {
            return self::walk($filter->get());
        }

        if (!$filter instanceof FilterAttributeInterface) {
            return null;
        }

        $attribute = $filter->getAttribute();

        if ($attribute === null) {
            return null;
        }

        return [Attribute::normalizeName($attribute)];
    }

    /**
     * @param array<FilterInterface> $children
     * @return list<string>|null
     */
    private static function walkChildren(array $children): ?array
    {
        $names = [];

        foreach ($children as $child) {
            $childNames = self::walk($child);

            if ($childNames === null) {
                return null;
            }

            $names = array_merge(
                $names,
                $childNames,
            );
        }

        return $names;
    }
}
