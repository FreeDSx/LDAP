<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\LessThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;
use PhpSpec\ObjectBehavior;

class FiltersSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(Filters::class);
    }

    function it_should_create_an_and_filter()
    {
        $this::and(new EqualityFilter('foo', 'bar'), new EqualityFilter('bar', 'foo'))->shouldBeLike(new AndFilter(
            new EqualityFilter('foo', 'bar'),
            new EqualityFilter('bar', 'foo')
        ));
    }

    function it_should_create_an_or_filter()
    {
        $this::or(new EqualityFilter('foo', 'bar'), new EqualityFilter('bar', 'foo'))->shouldBeLike(new OrFilter(
            new EqualityFilter('foo', 'bar'),
            new EqualityFilter('bar', 'foo')
        ));
    }

    function it_should_create_an_equality_filter()
    {
        $this::equal('foo', 'bar')->shouldBeLike(new EqualityFilter('foo', 'bar'));
    }

    function it_should_create_an_approximate_filter()
    {
        $this::approximate('foo', 'bar')->shouldBeLike(new ApproximateFilter('foo', 'bar'));
    }

    function it_should_create_a_greater_than_or_equal_filter()
    {
        $this::greaterThanOrEqual('foo', 'bar')->shouldBeLike(new GreaterThanOrEqualFilter('foo', 'bar'));
    }

    function it_should_have_gte_as_an_alias()
    {
        $this::gte('foo', 'bar')->shouldBeLike(new GreaterThanOrEqualFilter('foo', 'bar'));
    }

    function it_should_create_a_less_than_or_equal_filter()
    {
        $this::lessThanOrEqual('foo', 'bar')->shouldBeLike(new LessThanOrEqualFilter('foo', 'bar'));
    }

    function it_should_have_lte_as_an_alias()
    {
        $this::lte('foo', 'bar')->shouldBeLike(new LessThanOrEqualFilter('foo', 'bar'));
    }

    function it_should_create_a_substring_filter()
    {
        $this::substring('foo', 'fo', 'ob', 'ar')->shouldBeLike(new SubstringFilter('foo','fo', 'ob', 'ar'));
    }

    function it_should_create_a_substring_starts_with_filter()
    {
        $this::startsWith('foo', 'bar')->shouldBeLike(new SubstringFilter('foo', 'bar'));
    }

    function it_should_create_a_substring_ends_with_filter()
    {
        $this::endsWith('foo', 'bar')->shouldBeLike(new SubstringFilter('foo', null, 'bar'));
    }

    function it_should_create_a_substring_contains_filter()
    {
        $this::contains('foo', 'bar', 'foo')->shouldBeLike(new SubstringFilter('foo', null, null, 'bar', 'foo'));
    }

    function it_should_create_an_extensible_filter()
    {
        $this::extensible('foo', 'bar', 'foobar')->shouldBeLike(new MatchingRuleFilter('foobar', 'foo', 'bar'));
    }

    function it_should_create_a_not_filter()
    {
        $this::not(new EqualityFilter('foo', 'bar'))->shouldBeLike(new NotFilter(new EqualityFilter('foo', 'bar')));
    }

    function it_should_create_a_filter_from_a_raw_string_filter()
    {
        $this::raw('(foo=*)')->shouldBeLike(new PresentFilter('foo'));
        $this::raw('foo=bar')->shouldBeLike(new EqualityFilter('foo', 'bar'));
    }
}
