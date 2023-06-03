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
    public function let(): void
    {
        $this->beConstructedWith('foo');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(PresentFilter::class);
    }

    public function it_should_implement_fiter_interface(): void
    {
        $this->shouldImplement(FilterInterface::class);
    }

    public function it_should_get_the_attribute_name(): void
    {
        $this->getAttribute()->shouldBeEqualTo('foo');
    }

    public function it_should_generate_correct_asn1(): void
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(7, Asn1::octetString('foo')));
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $this::fromAsn1((new PresentFilter('foo'))->toAsn1())->shouldBeLike(new PresentFilter('foo'));
    }

    public function it_should_get_the_string_filter_representation(): void
    {
        $this->toString()->shouldBeEqualTo('(foo=*)');
    }

    public function it_should_have_a_filter_as_a_toString_representation(): void
    {
        $this->__toString()->shouldBeEqualTo('(foo=*)');
    }
}
