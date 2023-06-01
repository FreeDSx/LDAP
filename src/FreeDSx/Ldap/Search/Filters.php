<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Exception\FilterParseException;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\LessThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;

/**
 * Provides some simple factory methods for building filters.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Filters
{
    /**
     * Create a logical 'and' filter, containing other filters.
     */
    public static function and(FilterInterface ...$filters): AndFilter
    {
        return new AndFilter(...$filters);
    }

    /**
     * Create a logical 'or' filter, containing other filters.
     */
    public static function or(FilterInterface ...$filters): OrFilter
    {
        return new OrFilter(...$filters);
    }

    /**
     * Create a simple equality value check filter.
     */
    public static function equal(
        string $attribute,
        string $value,
    ): EqualityFilter {
        return new EqualityFilter(
            $attribute,
            $value
        );
    }

    /**
     * Create a filter to check for the negation of another filter.
     */
    public static function not(FilterInterface $filter): NotFilter
    {
        return new NotFilter($filter);
    }

    /**
     * A greater-than-or-equal-to check filter.
     */
    public static function greaterThanOrEqual(
        string $attribute,
        string $value,
    ): GreaterThanOrEqualFilter {
        return new GreaterThanOrEqualFilter(
            $attribute,
            $value,
        );
    }

    /**
     * An alias of greaterThanOrEqual.
     */
    public static function gte(
        string $attribute,
        string $value,
    ): GreaterThanOrEqualFilter {
        return self::greaterThanOrEqual(
            $attribute,
            $value,
        );
    }

    /**
     * A less-than-or-equal-to check filter.
     */
    public static function lessThanOrEqual(
        string $attribute,
        string $value,
    ): LessThanOrEqualFilter {
        return new LessThanOrEqualFilter(
            $attribute,
            $value,
        );
    }

    /**
     * An alias of lessThanOrEqual.
     */
    public static function lte(
        string $attribute,
        string $value
    ): LessThanOrEqualFilter {
        return self::lessThanOrEqual(
            $attribute,
            $value
        );
    }

    /**
     * Check if any attribute value is present.
     */
    public static function present(string $attribute): PresentFilter
    {
        return new PresentFilter($attribute);
    }

    /**
     * Create a substring filter (starts with, ends with, contains).
     */
    public static function substring(
        string $attribute,
        ?string $startsWith,
        ?string $endsWith,
        string ...$contains
    ): SubstringFilter {
        return new SubstringFilter(
            $attribute,
            $startsWith,
            $endsWith,
            ...$contains
        );
    }

    /**
     * Creates a substring filter to specifically check if an attribute value contains a value.
     */
    public static function contains(
        string $attribute,
        string ...$values
    ): SubstringFilter {
        return new SubstringFilter(
            $attribute,
            null,
            null,
            ...$values
        );
    }

    /**
     * Check if an attribute value ends with a specific value.
     */
    public static function endsWith(
        string $attribute,
        string $value
    ): SubstringFilter {
        return new SubstringFilter(
            $attribute,
            null,
            $value
        );
    }

    /**
     * Check if an attribute value starts with a specific value.
     */
    public static function startsWith(
        string $attribute,
        string $value
    ): SubstringFilter {
        return new SubstringFilter(
            $attribute,
            $value,
        );
    }

    /**
     * Create an extensible matching rule.
     */
    public static function extensible(
        ?string $attribute,
        string $value,
        ?string $rule,
        bool $matchDn = false
    ): MatchingRuleFilter {
        return new MatchingRuleFilter(
            $rule,
            $attribute,
            $value,
            $matchDn
        );
    }

    /**
     * Create an approximate equality check (directory specific implementation).
     */
    public static function approximate(
        string $attribute,
        string $value,
    ): ApproximateFilter {
        return new ApproximateFilter(
            $attribute,
            $value,
        );
    }

    /**
     * Create a filter object based off a string LDAP filter. For example, the filter "(cn=foo)" would return an
     * equality filter object.
     *
     * @throws FilterParseException
     */
    public static function raw(string $filter): FilterInterface
    {
        return FilterParser::parse($filter);
    }
}
