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
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use PhpSpec\ObjectBehavior;

class GreaterThanOrEqualFilterSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('foo', 'bar');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(GreaterThanOrEqualFilter::class);
    }

    public function it_should_implement_fiter_interface(): void
    {
        $this->shouldImplement(FilterInterface::class);
    }

    public function it_should_get_the_attribute_name(): void
    {
        $this->getAttribute()->shouldBeEqualTo('foo');
    }

    public function it_should_get_the_value(): void
    {
        $this->getValue()->shouldBeEqualTo('bar');
    }

    public function it_should_generate_correct_asn1(): void
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(5, Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::octetString('bar')
        )));
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $this::fromAsn1((new GreaterThanOrEqualFilter('foo', 'bar'))->toAsn1())->shouldBeLike(new GreaterThanOrEqualFilter('foo', 'bar'));
    }

    public function it_should_get_the_string_filter_representation(): void
    {
        $this->toString()->shouldBeEqualTo('(foo>=bar)');
    }

    public function it_should_have_a_filter_as_a_toString_representation(): void
    {
        $this->__toString()->shouldBeEqualTo('(foo>=bar)');
    }

    public function it_should_escape_values_on_the_string_representation(): void
    {
        $this->beConstructedWith('foo', ')(bar=*5');
        $this->toString()->shouldBeEqualTo('(foo>=\29\28bar=\2a5)');
    }
}
