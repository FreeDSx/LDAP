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

use FreeDSx\Ldap\Exception\FilterParseException;
use FreeDSx\Ldap\Search\Filters;
use PhpSpec\ObjectBehavior;

class FilterParserSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo');
    }

    function it_should_parse_an_equals_filter()
    {
        $this::parse('(foo=bar)')->shouldBeLike(Filters::equal('foo', 'bar'));
    }

    function it_should_parse_an_approximate_filter()
    {
        $this::parse('(foo~=bar)')->shouldBeLike(Filters::approximate('foo', 'bar'));
    }

    function it_should_parse_a_greater_than_or_equals_filter()
    {
        $this::parse('(foo>=1)')->shouldBeLike(Filters::gte('foo', '1'));
    }

    function it_should_parse_a_less_than_or_equals_filter()
    {
        $this::parse('(foo<=1)')->shouldBeLike(Filters::lte('foo', '1'));
    }

    function it_should_parse_a_present_filter()
    {
        $this->parse('(foo=*)')->shouldBeLike(Filters::present('foo'));
    }

    function it_should_parse_a_substring_starts_with_filter()
    {
        $this::parse('(foo=bar*)')->shouldBeLike(Filters::startsWith('foo', 'bar'));
    }

    function it_should_parse_a_substring_ends_with_filter()
    {
        $this::parse('(foo=*bar)')->shouldBeLike(Filters::endsWith('foo', 'bar'));
    }

    function it_should_parse_a_substring_contains_filter()
    {
        $this::parse('(foo=*bar*)')->shouldBeLike(Filters::contains('foo', 'bar'));
    }

    function it_should_parse_a_mixed_substring_filter()
    {
        $this::parse('(foo=this*is*a*filter)')->shouldBeLike(Filters::substring('foo', 'this', 'filter', 'is', 'a'));
    }

    function it_should_parse_an_extensible_match_filter_with_an_attribute_only()
    {
        $this::parse('givenName:=Chad')->shouldBeLike(Filters::extensible('givenName', 'Chad', null));
    }

    function it_should_parse_an_extensible_match_filter_with_a_dn_and_matching_rule()
    {
        $this::parse(':dn:1.2.3:=Chad')->shouldBeLike(Filters::extensible(null, 'Chad' , null)->setUseDnAttributes(true)->setMatchingRule('1.2.3'));
    }

    function it_should_parse_an_extensible_match_filter_with_a_dn_and_attribute_type()
    {
        $this::parse('o:dn:=Chad')->shouldBeLike(Filters::extensible('o', 'Chad' , null)->setUseDnAttributes(true));
    }

    function it_should_error_on_invalid_matching_rule_syntax()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse', [':dn::=Chad']);
        $this->shouldThrow(FilterParseException::class)->during('parse', ['&^]:=Chad']);
        $this->shouldThrow(FilterParseException::class)->during('parse', ['?:=Chad']);
    }

    function it_should_error_when_parsing_an_extensible_match_with_no_matching_rule_or_type()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse', [':dn:=Chad']);
    }

    function it_should_parse_a_simple_comparison_filter_without_parenthesis()
    {
        $this::parse('foo=bar')->shouldBeLike(Filters::equal('foo', 'bar'));
    }

    function it_should_parse_an_and_filter()
    {
        $this::parse('(&(foo=bar)(bar~=foo))')->shouldBeLike(Filters::and(
            Filters::equal('foo', 'bar'),
            Filters::approximate('bar', 'foo')
        ));
    }

    function it_should_parse_an_or_filter()
    {
        $this::parse('(|(foo=bar)(bar~=foo))')->shouldBeLike(Filters::or(
            Filters::equal('foo', 'bar'),
            Filters::approximate('bar', 'foo')
        ));
    }

    function it_should_parse_filter_containers_with_nested_containers()
    {
        $this::parse('(&(|(foo=*bar)(bar<=5))(foo~=bar))')->shouldBeLike(Filters::and(
            Filters::or(Filters::endsWith('foo', 'bar'), Filters::lte('bar', '5')),
            Filters::approximate('foo', 'bar')
        ));
        $this::parse('(&(|(foo=*bar)(bar<=5))(foo~=bar)(&(foo=bar)(|(bar=*)(cn=Chad))))')->shouldBeLike(Filters::and(
            Filters::or(Filters::endsWith('foo', 'bar'), Filters::lte('bar', '5')),
            Filters::approximate('foo', 'bar'),
            Filters::and(
                Filters::equal('foo', 'bar'),
                Filters::or(
                    Filters::present('bar'),
                    Filters::equal('cn','Chad')
                )
            )
        ));
    }

    function it_should_parse_a_not_filter()
    {
        $this::parse('(!(foo=bar))')->shouldBeLike(Filters::not(Filters::equal('foo', 'bar')));
    }

    function it_should_not_allow_a_not_filter_to_contain_more_than_one_filter()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse', ['(!(&(foo=bar)))']);
    }

    function it_should_decode_hex_encoded_values()
    {
        $this::parse('o=Parens R Us \28for all your parenthetical needs\29')->shouldBeLike(Filters::equal('o','Parens R Us (for all your parenthetical needs)'));
        $this::parse('(cn=*\2A*)')->shouldBeLike(Filters::contains('cn', '*'));
        $this::parse('(bin=\00\00\00\04)')->shouldBeLike(Filters::equal('bin', "\x00\x00\x00\x04" ));
        $this::parse('(sn=Lu\c4\8di\c4\87)')->shouldBeLike(Filters::equal('sn', 'Lučić'));
    }

    function it_should_error_on_nested_unmatched_parenthesis()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse',['(&(foo=bar)(|(&(foo=bar)))']);
    }

    function it_should_error_on_an_unmatched_parenthesis()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse', ['foo=bar)']);
    }

    function it_should_error_on_unrecognized_values_at_the_end_of_the_filter()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse', ['(foo=bar)(foo)']);
        $this->shouldThrow(FilterParseException::class)->during('parse', ['(foo=bar)foo']);
    }

    function it_should_error_on_empty_values()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse', ['(foo=)']);
    }

    function it_should_error_on_unrecognized_operators()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse', ['(foo>4)']);
    }

    function it_should_error_on_an_empty_attribute_in_the_filter()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse', ['(=bar)']);
    }

    function it_should_error_on_empty_containers()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse', ['(&)']);
    }

    function it_should_error_on_an_empty_filter()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse', ['']);
    }

    function it_should_error_on_a_malformed_container()
    {
        $this->shouldThrow(FilterParseException::class)->during('parse', ['(&']);
    }
}
