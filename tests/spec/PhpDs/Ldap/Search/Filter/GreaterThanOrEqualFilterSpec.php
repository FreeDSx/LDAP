<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Search\Filter;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Search\Filter\FilterInterface;
use PhpDs\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use PhpSpec\ObjectBehavior;

class GreaterThanOrEqualFilterSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo', 'bar');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(GreaterThanOrEqualFilter::class);
    }

    function it_should_implement_fiter_interface()
    {
        $this->shouldImplement(FilterInterface::class);
    }

    function it_should_get_the_attribute_name()
    {
        $this->getAttribute()->shouldBeEqualTo('foo');
    }

    function it_should_get_the_value()
    {
        $this->getValue()->shouldBeEqualTo('bar');
    }

    function it_should_generate_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(5, Asn1::sequence(
            Asn1::ldapString('foo'),
            Asn1::octetString('bar')
        )));
    }
}
