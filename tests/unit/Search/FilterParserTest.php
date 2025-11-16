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

use FreeDSx\Ldap\Exception\FilterParseException;
use FreeDSx\Ldap\Search\FilterParser;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;

final class FilterParserTest extends TestCase
{
    public function test_it_should_parse_an_equals_filter(): void
    {
        self::assertEquals(
            Filters::equal('foo', 'bar'),
            FilterParser::parse('(foo=bar)'),
        );
    }

    public function test_it_should_parse_an_approximate_filter(): void
    {
        self::assertEquals(
            Filters::approximate('foo', 'bar'),
            FilterParser::parse('(foo~=bar)'),
        );
    }

    public function test_it_should_parse_a_greater_than_or_equals_filter(): void
    {
        self::assertEquals(
            Filters::gte('foo', '1'),
            FilterParser::parse('(foo>=1)'),
        );
    }

    public function test_it_should_parse_a_less_than_or_equals_filter(): void
    {
        self::assertEquals(
            Filters::lte('foo', '1'),
            FilterParser::parse('(foo<=1)'),
        );
    }

    public function test_it_should_parse_a_present_filter(): void
    {
        self::assertEquals(
            Filters::present('foo'),
            FilterParser::parse('(foo=*)'),
        );
    }

    public function test_it_should_parse_a_substring_starts_with_filter(): void
    {
        self::assertEquals(
            Filters::startsWith('foo', 'bar'),
            FilterParser::parse('(foo=bar*)'),
        );
    }

    public function test_it_should_parse_a_substring_ends_with_filter(): void
    {
        self::assertEquals(
            Filters::endsWith('foo', 'bar'),
            FilterParser::parse('(foo=*bar)'),
        );
    }

    public function test_it_should_parse_a_substring_contains_filter(): void
    {
        self::assertEquals(
            Filters::contains('foo', 'bar'),
            FilterParser::parse('(foo=*bar*)'),
        );
    }

    public function test_it_should_parse_a_mixed_substring_filter(): void
    {
        self::assertEquals(
            Filters::substring('foo', 'this', 'filter', 'is', 'a'),
            FilterParser::parse('(foo=this*is*a*filter)'),
        );
    }

    public function test_it_should_parse_an_extensible_match_filter_with_an_attribute_only(): void
    {
        self::assertEquals(
            Filters::extensible('foo', 'bar', null),
            FilterParser::parse('foo:=bar'),
        );
    }

    public function test_it_should_parse_an_extensible_match_filter_with_a_dn_and_matching_rule(): void
    {
        self::assertEquals(
            Filters::extensible(null, 'Chad', '1.2.3')
                ->setUseDnAttributes(true),
            FilterParser::parse(':dn:1.2.3:=Chad'),
        );
    }

    public function test_it_should_parse_an_extensible_match_filter_with_a_dn_and_attribute_type(): void
    {
        self::assertEquals(
            Filters::extensible('o', 'Chad', null)
                ->setUseDnAttributes(true),
            FilterParser::parse('o:dn:=Chad'),
        );
    }

    /**
     * @dataProvider invalidMatchingRuleDataProvider
     */
    public function test_it_should_error_on_invalid_matching_rule_syntax(string $filter): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse($filter);
    }

    public function test_it_should_error_when_parsing_an_extensible_match_with_no_matching_rule_or_type(): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse(':dn:=Chad');
    }

    public function test_it_should_parse_a_simple_comparison_filter_without_parenthesis(): void
    {
        self::assertEquals(
            Filters::equal('foo', 'bar'),
            FilterParser::parse('foo=bar'),
        );
    }

    public function test_it_should_parse_an_and_filter(): void
    {
        self::assertEquals(
            Filters::and(
                Filters::equal('foo', 'bar'),
                Filters::approximate('bar', 'foo'),
            ),
            FilterParser::parse('(&(foo=bar)(bar~=foo))'),
        );
    }

    public function test_it_should_parse_an_or_filter(): void
    {
        self::assertEquals(
            Filters::or(
                Filters::equal('foo', 'bar'),
                Filters::approximate('bar', 'foo'),
            ),
            FilterParser::parse('(|(foo=bar)(bar~=foo))'),
        );
    }

    public function test_it_should_parse_filter_containers_with_nested_containers(): void
    {
        self::assertEquals(
            Filters::and(
                Filters::or(
                    Filters::endsWith('foo', 'bar'),
                    Filters::lte('bar', '5'),
                ),
                Filters::approximate('foo', 'bar'),
            ),
            FilterParser::parse('(&(|(foo=*bar)(bar<=5))(foo~=bar))'),
        );

        self::assertEquals(
            Filters::and(
                Filters::or(
                    Filters::endsWith('foo', 'bar'),
                    Filters::lte('bar', '5'),
                ),
                Filters::approximate('foo', 'bar'),
                Filters::and(
                    Filters::equal('foo', 'bar'),
                    Filters::or(
                        Filters::present('bar'),
                        Filters::equal('cn', 'Chad'),
                    )
                )
            ),
            FilterParser::parse('(&(|(foo=*bar)(bar<=5))(foo~=bar)(&(foo=bar)(|(bar=*)(cn=Chad))))'),
        );
    }

    public function test_it_should_parse_a_not_filter(): void
    {
        self::assertEquals(
            Filters::not(Filters::equal('foo', 'bar')),
            FilterParser::parse('(!(foo=bar))'),
        );
    }

    public function test_it_should_not_allow_a_not_filter_to_contain_more_than_one_filter(): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse('(!(foo=bar)(bar=baz))');
    }

    public function test_it_should_decode_hex_encoded_values(): void
    {
        self::assertEquals(
            Filters::equal('o', 'Parens R Us (for all your parenthetical needs)'),
            FilterParser::parse('(o=Parens R Us \28for all your parenthetical needs\29)'),
        );

        self::assertEquals(
            Filters::contains('cn', '*'),
            FilterParser::parse('(cn=*\2A*)'),
        );

        self::assertEquals(
            Filters::equal('bin', "\x00\x00\x00\x04"),
            FilterParser::parse('(bin=\00\00\00\04)'),
        );

        self::assertEquals(
            Filters::equal('sn', 'Lučić'),
            FilterParser::parse('(sn=Lu\c4\8di\c4\87)'),
        );
    }

    public function test_it_should_error_on_nested_unmatched_parenthesis(): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse('(&(foo=bar)(|(&(foo=bar)))');
    }

    public function test_it_should_error_on_an_unmatched_parenthesis(): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse('foo=bar)');
    }

    /**
     * @dataProvider malformedFilterDataProvider
     */
    public function test_it_should_error_on_unrecognized_values_at_the_end_of_the_filter(string $filter): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse($filter);
    }

    public function test_it_should_error_on_empty_values(): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse('(foo=)');
    }

    public function test_it_should_error_on_unrecognized_operators(): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse('(foo>4)');
    }

    public function test_it_should_error_on_an_empty_attribute_in_the_filter(): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse('(=bar)');
    }

    public function test_it_should_error_on_empty_containers(): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse('(&)');
    }

    public function test_it_should_error_on_an_empty_filter(): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse('');
    }

    public function test_it_should_error_on_a_malformed_container(): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse('(&');
    }

    /**
     * @return array<array{string}>
     */
    public static function malformedFilterDataProvider(): array
    {
        return [
            ['(foo=bar)(foo)'],
            ['(foo=bar)foo']
        ];
    }

    /**
     * @return array<array{string}>
     */
    public static function invalidMatchingRuleDataProvider(): array
    {
        return [
            [':dn::=Chad'],
            ['&^]:=Chad'],
            ['?:=Chad']
        ];
    }
}
