<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Search\Filter;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use PhpSpec\ObjectBehavior;

class MatchingRuleFilterSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo', 'bar', 'foobar');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(MatchingRuleFilter::class);
    }

    function it_should_implement_fiter_interface()
    {
        $this->shouldImplement(FilterInterface::class);
    }

    function it_should_get_the_attribute_name()
    {
        $this->getAttribute()->shouldBeEqualTo('bar');
    }

    function it_should_get_the_value()
    {
        $this->getValue()->shouldBeEqualTo('foobar');
    }

    function it_should_not_use_dn_attributes_by_default()
    {
        $this->getUseDnAttributes()->shouldBeEqualTo(false);
    }

    function it_should_set_whether_to_use_dn_attributes_by_default()
    {
        $this->setUseDnAttributes(true);
        $this->getUseDnAttributes()->shouldBeEqualTo(true);
    }

    function it_should_set_the_matching_rule()
    {
        $this->setMatchingRule('bleep');
        $this->getMatchingRule()->shouldBeEqualTo('bleep');
    }

    function it_should_be_able_to_set_the_attribute_to_null()
    {
        $this->setAttribute(null);
        $this->getAttribute()->shouldBeNull();
    }

    function it_should_be_able_to_set_the_matching_rule_to_null()
    {
        $this->setMatchingRule(null);
        $this->getMatchingRule()->shouldBeNull();
    }

    function it_should_generate_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(9, Asn1::sequence(
            Asn1::context(1, Asn1::octetString('foo')),
            Asn1::context(2, Asn1::octetString('bar')),
            Asn1::context(3, Asn1::octetString('foobar')),
            Asn1::context(4, Asn1::boolean(false))
        )));

        $this->setUseDnAttributes(true);
        $this->toAsn1()->shouldBeLike(Asn1::context(9, Asn1::sequence(
            Asn1::context(1, Asn1::octetString('foo')),
            Asn1::context(2, Asn1::octetString('bar')),
            Asn1::context(3, Asn1::octetString('foobar')),
            Asn1::context(4, Asn1::boolean(true))
        )));

        $this->setMatchingRule(null);
        $this->toAsn1()->shouldBeLike(Asn1::context(9, Asn1::sequence(
            Asn1::context(2, Asn1::octetString('bar')),
            Asn1::context(3, Asn1::octetString('foobar')),
            Asn1::context(4, Asn1::boolean(true))
        )));

        $this->setAttribute(null);
        $this->toAsn1()->shouldBeLike(Asn1::context(9, Asn1::sequence(
            Asn1::context(3, Asn1::octetString('foobar')),
            Asn1::context(4, Asn1::boolean(true))
        )));
    }

    function it_should_be_constructed_from_asn1()
    {
        $rule = new MatchingRuleFilter('foo', 'foo', 'bar', true);

        $this->fromAsn1($rule->toAsn1())->shouldBeLike($rule);
    }

    function it_should_get_the_string_filter_representation()
    {
        $this->toString()->shouldBeEqualTo('(bar:foo:=foobar)');
    }

    function it_should_get_the_filter_representation_with_a_dn_match()
    {
        $this->setUseDnAttributes(true);

        $this->toString()->shouldBeEqualTo('(bar:foo:dn:=foobar)');
    }

    function it_should_have_a_filter_as_a_toString_representation()
    {
        $this->__toString()->shouldBeEqualTo('(bar:foo:=foobar)');
    }

    function it_should_escape_values_on_the_string_representation()
    {
        $this->beConstructedWith('foo', 'bar', ')(bar=*5');
        $this->toString()->shouldBeEqualTo('(bar:foo:=\29\28bar=\2a5)');
    }
}
