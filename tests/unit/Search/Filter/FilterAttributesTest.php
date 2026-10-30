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

namespace Tests\Unit\FreeDSx\Ldap\Search\Filter;

use FreeDSx\Ldap\Search\Filter\FilterAttributes;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;

final class FilterAttributesTest extends TestCase
{
    public function test_it_collects_a_single_leaf_attribute_lowercased(): void
    {
        self::assertSame(
            ['cn'],
            FilterAttributes::referenced(Filters::equal('CN', 'x')),
        );
    }

    public function test_it_strips_attribute_options_to_the_base_name(): void
    {
        self::assertSame(
            ['cn'],
            FilterAttributes::referenced(Filters::equal('cn;lang-en', 'x')),
        );
    }

    public function test_it_walks_and_or_not_and_dedupes(): void
    {
        $filter = Filters::and(
            Filters::equal('cn', 'x'),
            Filters::or(
                Filters::startsWith('mail', 'y'),
                Filters::present('objectClass'),
            ),
            Filters::not(Filters::gte('uidNumber', '5')),
            Filters::equal('cn', 'z'),
        );

        self::assertSame(
            ['cn', 'mail', 'objectclass', 'uidnumber'],
            FilterAttributes::referenced($filter),
        );
    }

    public function test_it_returns_a_numeric_name_as_a_string(): void
    {
        self::assertSame(
            ['123', 'cn'],
            FilterAttributes::referenced(Filters::or(
                Filters::equal(
                    '123',
                    'x',
                ),
                Filters::equal(
                    'cn',
                    'y',
                ),
                Filters::equal(
                    '123',
                    'z',
                ),
            )),
        );
    }

    public function test_it_collects_the_extensible_match_attribute_when_present(): void
    {
        self::assertSame(
            ['cn'],
            FilterAttributes::referenced(new MatchingRuleFilter('caseIgnoreMatch', 'cn', 'x')),
        );
    }

    public function test_an_extensible_match_without_an_attribute_is_indeterminate(): void
    {
        self::assertNull(FilterAttributes::referenced(new MatchingRuleFilter('caseIgnoreMatch', null, 'x')));
    }

    public function test_any_indeterminate_leaf_makes_the_whole_filter_indeterminate(): void
    {
        $filter = Filters::and(
            Filters::equal('cn', 'x'),
            new MatchingRuleFilter('caseIgnoreMatch', null, 'x'),
        );

        self::assertNull(FilterAttributes::referenced($filter));
    }
}
