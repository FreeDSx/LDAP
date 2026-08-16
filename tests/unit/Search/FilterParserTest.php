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
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\FilterParser;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
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

    #[DataProvider('invalidMatchingRuleDataProvider')]
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
                    ),
                ),
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

    /**
     * RFC 4515 3 defines "not" over any single filter, which includes a nested container.
     */
    public function test_it_should_parse_a_not_filter_wrapping_a_container(): void
    {
        self::assertEquals(
            Filters::not(Filters::and(
                Filters::equal('foo', 'bar'),
                Filters::equal('bar', 'baz'),
            )),
            FilterParser::parse('(!(&(foo=bar)(bar=baz)))'),
        );
    }

    public function test_it_should_unescape_the_initial_substring(): void
    {
        self::assertEquals(
            Filters::startsWith('cn', '*a'),
            FilterParser::parse('(cn=\2aa*)'),
        );
    }

    public function test_it_should_unescape_the_final_substring(): void
    {
        self::assertEquals(
            Filters::endsWith('cn', 'a*'),
            FilterParser::parse('(cn=*a\2a)'),
        );
    }

    public function test_it_should_only_use_dn_attributes_when_asked_to(): void
    {
        $withoutDn = FilterParser::parse('(cn:2.5.13.5:=foo)');
        $withDn = FilterParser::parse('(cn:dn:2.5.13.5:=foo)');

        self::assertInstanceOf(MatchingRuleFilter::class, $withoutDn);
        self::assertInstanceOf(MatchingRuleFilter::class, $withDn);
        self::assertFalse($withoutDn->getUseDnAttributes());
        self::assertTrue($withDn->getUseDnAttributes());
    }

    public function test_it_should_accept_dn_attributes_in_any_case(): void
    {
        $filter = FilterParser::parse('(:DN:2.4.6.8.10:=Dino)');

        self::assertInstanceOf(MatchingRuleFilter::class, $filter);
        self::assertTrue($filter->getUseDnAttributes());
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

    /**
     * @param non-empty-string $filter
     */
    #[DataProvider('malformedValueEncodingProvider')]
    public function test_it_should_error_on_a_value_outside_the_rfc_4515_encoding(string $filter): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse($filter);
    }

    /**
     * RFC 4515 3: escaped is ESC HEX HEX, and UTF1SUBSET excludes NUL, the parentheses and the asterisk.
     *
     * @return iterable<string, array{non-empty-string}>
     */
    public static function malformedValueEncodingProvider(): iterable
    {
        yield 'a backslash followed by no hex digits' => [
            '(cn=a\zz)',
        ];
        yield 'a backslash at the end of a value' => [
            '(cn=a\)',
        ];
        yield 'a backslash followed by one hex digit' => [
            '(cn=a\5)',
        ];
        yield 'an unescaped opening parenthesis' => [
            '(cn=a(b)',
        ];
        yield 'a raw null byte' => [
            "(cn=a\x00b)",
        ];
    }

    /**
     * @param non-empty-string $filter
     */
    #[DataProvider('wellFormedValueEncodingProvider')]
    public function test_it_should_accept_a_value_within_the_rfc_4515_encoding(string $filter): void
    {
        self::assertSame(
            $filter,
            FilterParser::parse($filter)->toString(),
        );
    }

    /**
     * @return iterable<string, array{non-empty-string}>
     */
    public static function wellFormedValueEncodingProvider(): iterable
    {
        yield 'an escaped backslash' => [
            '(cn=a\5cb)',
        ];
        yield 'an escaped parenthesis' => [
            '(cn=a\28b)',
        ];
        yield 'an escaped asterisk' => [
            '(cn=a\2ab)',
        ];
        yield 'an escaped null' => [
            '(cn=a\00b)',
        ];
        yield 'a substring, whose asterisks are structural' => [
            '(cn=a*b*c)',
        ];
        yield 'a multibyte value' => [
            '(cn=Ω)',
        ];
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

    #[DataProvider('malformedFilterDataProvider')]
    public function test_it_should_error_on_unrecognized_values_at_the_end_of_the_filter(string $filter): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse($filter);
    }

    /**
     * RFC 4515 3 permits an empty assertionvalue, and section 4 gives "(seeAlso=)" as an example.
     */
    public function test_it_should_accept_an_empty_value(): void
    {
        self::assertSame(
            '(foo=)',
            FilterParser::parse('(foo=)')->toString(),
        );
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

    public function test_it_should_parse_rfc_4526_absolute_true_filter(): void
    {
        $filter = FilterParser::parse('(&)');

        self::assertInstanceOf(
            AndFilter::class,
            $filter,
        );
        self::assertEquals(
            Filters::and(),
            $filter,
        );
        self::assertCount(
            0,
            $filter,
        );
        self::assertSame(
            '(&)',
            $filter->toString(),
        );
    }

    public function test_it_should_parse_rfc_4526_absolute_false_filter(): void
    {
        $filter = FilterParser::parse('(|)');

        self::assertInstanceOf(
            OrFilter::class,
            $filter,
        );
        self::assertEquals(
            Filters::or(),
            $filter,
        );
        self::assertCount(
            0,
            $filter,
        );
        self::assertSame(
            '(|)',
            $filter->toString(),
        );
    }

    public function test_rfc_4526_absolute_filters_round_trip_through_a_nested_container(): void
    {
        self::assertEquals(
            Filters::and(
                Filters::equal('cn', 'foo'),
                Filters::or(),
            ),
            FilterParser::parse('(&(cn=foo)(|))'),
        );
    }

    public function test_it_should_error_on_an_empty_not_filter_container(): void
    {
        self::expectException(FilterParseException::class);

        FilterParser::parse('(!)');
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
            ['(foo=bar)foo'],
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
            ['?:=Chad'],
        ];
    }
}
