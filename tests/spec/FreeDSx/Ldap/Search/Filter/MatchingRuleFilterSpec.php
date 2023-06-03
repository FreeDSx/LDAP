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

namespace spec\FreeDSx\Ldap\Search\Filter;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use PhpSpec\ObjectBehavior;

class MatchingRuleFilterSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('foo', 'bar', 'foobar');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(MatchingRuleFilter::class);
    }

    public function it_should_implement_fiter_interface(): void
    {
        $this->shouldImplement(FilterInterface::class);
    }

    public function it_should_get_the_attribute_name(): void
    {
        $this->getAttribute()->shouldBeEqualTo('bar');
    }

    public function it_should_get_the_value(): void
    {
        $this->getValue()->shouldBeEqualTo('foobar');
    }

    public function it_should_not_use_dn_attributes_by_default(): void
    {
        $this->getUseDnAttributes()->shouldBeEqualTo(false);
    }

    public function it_should_set_whether_to_use_dn_attributes_by_default(): void
    {
        $this->setUseDnAttributes(true);
        $this->getUseDnAttributes()->shouldBeEqualTo(true);
    }

    public function it_should_set_the_matching_rule(): void
    {
        $this->setMatchingRule('bleep');
        $this->getMatchingRule()->shouldBeEqualTo('bleep');
    }

    public function it_should_be_able_to_set_the_attribute_to_null(): void
    {
        $this->setAttribute(null);
        $this->getAttribute()->shouldBeNull();
    }

    public function it_should_be_able_to_set_the_matching_rule_to_null(): void
    {
        $this->setMatchingRule(null);
        $this->getMatchingRule()->shouldBeNull();
    }

    public function it_should_generate_correct_asn1(): void
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

    public function it_should_be_constructed_from_asn1(): void
    {
        $rule = new MatchingRuleFilter('foo', 'foo', 'bar', true);

        $this->fromAsn1($rule->toAsn1())->shouldBeLike($rule);
    }

    public function it_should_get_the_string_filter_representation(): void
    {
        $this->toString()->shouldBeEqualTo('(bar:foo:=foobar)');
    }

    public function it_should_get_the_filter_representation_with_a_dn_match(): void
    {
        $this->setUseDnAttributes(true);

        $this->toString()->shouldBeEqualTo('(bar:foo:dn:=foobar)');
    }

    public function it_should_have_a_filter_as_a_toString_representation(): void
    {
        $this->__toString()->shouldBeEqualTo('(bar:foo:=foobar)');
    }

    public function it_should_escape_values_on_the_string_representation(): void
    {
        $this->beConstructedWith('foo', 'bar', ')(bar=*5');
        $this->toString()->shouldBeEqualTo('(bar:foo:=\29\28bar=\2a5)');
    }
}
