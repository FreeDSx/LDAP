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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterContainerInterface;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;
use FreeDSx\Ldap\Search\Filters;
use PhpSpec\ObjectBehavior;

class AndFilterSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(Filters::equal('foo', 'bar'), Filters::gte('foo', '2'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(AndFilter::class);
    }

    function it_should_implement_fiter_interface()
    {
        $this->shouldImplement(FilterInterface::class);
    }

    function it_should_implement_filter_container_interface()
    {
        $this->shouldImplement(FilterContainerInterface::class);
    }

    function it_should_implement_countable()
    {
        $this->shouldImplement('\Countable');
    }

    function it_should_implement_iterator_aggregate()
    {
        $this->shouldImplement('\IteratorAggregate');
    }

    function it_should_get_the_filters_it_contains()
    {
        $this->get()->shouldBeLike([
           Filters::equal('foo', 'bar'),
           Filters::gte('foo', 2)
        ]);
    }

    function it_should_set_the_filters()
    {
        $this->set(Filters::equal('bar', 'foo'));

        $this->get()->shouldBeLike([Filters::equal('bar', 'foo')]);
    }

    function it_should_add_to_the_filters()
    {
        $filter = Filters::equal('foobar', 'foobar');

        $this->add($filter);
        $this->get()->shouldContain($filter);
    }

    function it_should_remove_from_the_filters()
    {
        $filter = Filters::equal('foobar', 'foobar');

        $this->add($filter);
        $this->get()->shouldContain($filter);

        $this->remove($filter);
        $this->get()->shouldNotContain($filter);
    }

    function it_should_check_if_a_filter_exists()
    {
        $filter = Filters::equal('foobar', 'foobar');

        $this->has($filter)->shouldBeEqualTo(false);
        $this->add($filter);
        $this->has($filter)->shouldBeEqualTo(true);
    }

    function it_should_generate_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(0, Asn1::setOf(
            Filters::equal('foo', 'bar')->toAsn1(),
            Filters::gte('foo', '2')->toAsn1()
        )));
    }

    function it_should_be_constructed_from_asn1()
    {
        $and = new AndFilter(new EqualityFilter('foo', 'bar'), new SubstringFilter('bar', 'foo'));

        $this::fromAsn1($and->toAsn1())->shouldBeLike($and);
    }

    function it_should_not_be_constructed_from_invalid_asn1()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence()]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::octetString('foo')]);
    }

    function it_should_get_the_string_filter_representation()
    {
        $this->toString()->shouldBeEqualTo('(&(foo=bar)(foo>=2))');
    }

    function it_should_get_the_string_filter_representation_with_nested_containers()
    {
        $this->add(Filters::or(Filters::equal('foo', 'bar')));

        $this->toString()->shouldBeEqualTo('(&(foo=bar)(foo>=2)(|(foo=bar)))');
    }

    function it_should_have_a_filter_as_a_toString_representation()
    {
        $this->__toString()->shouldBeEqualTo('(&(foo=bar)(foo>=2))');
    }

    function it_should_get_the_count()
    {
        $this->count()->shouldBeEqualTo(2);
    }
}
