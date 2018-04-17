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
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use PhpSpec\ObjectBehavior;

class PresentFilterSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(PresentFilter::class);
    }

    function it_should_implement_fiter_interface()
    {
        $this->shouldImplement(FilterInterface::class);
    }

    function it_should_get_the_attribute_name()
    {
        $this->getAttribute()->shouldBeEqualTo('foo');
    }

    function it_should_generate_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(7, Asn1::octetString('foo')));
    }

    function it_should_be_constructed_from_asn1()
    {
        $this::fromAsn1((new PresentFilter('foo'))->toAsn1())->shouldBeLike(new PresentFilter('foo'));
    }

    function it_should_get_the_string_filter_representation()
    {
        $this->toString()->shouldBeEqualTo('(foo=*)');
    }

    function it_should_have_a_filter_as_a_toString_representation()
    {
        $this->__toString()->shouldBeEqualTo('(foo=*)');
    }
}
