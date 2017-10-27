<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Search\Filter;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filters;
use PhpSpec\ObjectBehavior;

class OrFilterSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(Filters::equal('foo', 'bar'), Filters::gte('foo', '2'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(OrFilter::class);
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
        $this->toAsn1()->shouldBeLike(Asn1::context(1, Asn1::setOf(
            Filters::equal('foo', 'bar')->toAsn1(),
            Filters::gte('foo', '2')->toAsn1()
        )));
    }
}
