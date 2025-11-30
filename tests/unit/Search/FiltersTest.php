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

namespace Tests\Unit\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\LessThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;

final class FiltersTest extends TestCase
{
    public function test_it_should_create_an_and_filter(): void
    {
        self::assertEquals(
            new AndFilter(
                new EqualityFilter('foo', 'bar'),
                new EqualityFilter('bar', 'foo')
            ),
            Filters::and(
                new EqualityFilter('foo', 'bar'),
                new EqualityFilter('bar', 'foo'),
            )
        );
    }

    public function test_it_should_create_an_or_filter(): void
    {
        self::assertEquals(
            new OrFilter(
                new EqualityFilter('foo', 'bar'),
                new EqualityFilter('bar', 'foo'),
            ),
            Filters::or(
                new EqualityFilter('foo', 'bar'),
                new EqualityFilter('bar', 'foo'),
            )
        );
    }

    public function test_it_should_create_an_equality_filter(): void
    {
        self::assertEquals(
            new EqualityFilter('foo', 'bar'),
            Filters::equal('foo', 'bar'),
        );
    }

    public function test_it_should_create_an_approximate_filter(): void
    {
        self::assertEquals(
            new ApproximateFilter('foo', 'bar'),
            Filters::approximate('foo', 'bar'),
        );
    }

    public function test_it_should_create_a_greater_than_or_equal_filter(): void
    {
        self::assertEquals(
            new GreaterThanOrEqualFilter('foo', 'bar'),
            Filters::gte('foo', 'bar'),
        );
    }

    public function test_it_should_have_gte_as_an_alias(): void
    {
        self::assertEquals(
            new GreaterThanOrEqualFilter('foo', 'bar'),
            Filters::gte('foo', 'bar'),
        );
    }

    public function test_it_should_create_a_less_than_or_equal_filter(): void
    {
        self::assertEquals(
            new LessThanOrEqualFilter('foo', 'bar'),
            Filters::lte('foo', 'bar'),
        );
    }

    public function test_it_should_have_lte_as_an_alias(): void
    {
        self::assertEquals(
            new LessThanOrEqualFilter('foo', 'bar'),
            Filters::lte('foo', 'bar'),
        );
    }

    public function test_it_should_create_a_substring_filter(): void
    {
        self::assertEquals(
            new SubstringFilter('foo', 'fo', 'ob', 'ar'),
            Filters::substring('foo', 'fo', 'ob', 'ar'),
        );
    }

    public function test_it_should_create_a_substring_starts_with_filter(): void
    {
        self::assertEquals(
            new SubstringFilter('foo', 'bar'),
            Filters::startsWith('foo', 'bar'),
        );
    }

    public function test_it_should_create_a_substring_ends_with_filter(): void
    {
        self::assertEquals(
            new SubstringFilter('foo', null, 'bar'),
            Filters::endsWith('foo', 'bar'),
        );
    }

    public function test_it_should_create_a_substring_contains_filter(): void
    {
        self::assertEquals(
            new SubstringFilter('foo', null, null, 'bar'),
            Filters::contains('foo', 'bar'),
        );
    }

    public function test_it_should_create_an_extensible_filter(): void
    {
        self::assertEquals(
            new MatchingRuleFilter('foobar', 'foo', 'bar'),
            Filters::extensible('foo', 'bar', 'foobar'),
        );
    }

    public function test_it_should_create_a_not_filter(): void
    {
        self::assertEquals(
            new NotFilter(new EqualityFilter('foo', 'bar')),
            Filters::not(new EqualityFilter('foo', 'bar')),
        );
    }

    public function test_it_should_create_a_filter_from_a_raw_string_filter(): void
    {
        self::assertEquals(
            new EqualityFilter('foo', 'bar'),
            Filters::raw('foo=bar'),
        );
        self::assertEquals(
            new PresentFilter('foo'),
            Filters::raw('(foo=*)'),
        );
    }
}
