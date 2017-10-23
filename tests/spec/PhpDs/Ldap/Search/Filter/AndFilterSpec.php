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
use PhpDs\Ldap\Search\Filter\AndFilter;
use PhpDs\Ldap\Search\Filter\FilterInterface;
use PhpDs\Ldap\Search\Filters;
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
}
