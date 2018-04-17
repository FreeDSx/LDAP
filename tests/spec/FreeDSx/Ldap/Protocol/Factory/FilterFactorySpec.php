<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Protocol\Factory\FilterFactory;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PhpSpec\ObjectBehavior;

class FilterFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(FilterFactory::class);
    }

    function it_should_check_if_a_mapping_exists()
    {
        $this::has(0)->shouldBeEqualTo(true);
        $this::has(99)->shouldBeEqualTo(false);
    }

    function it_should_set_a_mapping()
    {
        $this::set(99, EqualityFilter::class);

        $this::has(99)->shouldBeEqualTo(true);
    }

    function it_should_get_a_mapping()
    {
        $this::get((new EqualityFilter('foo', 'bar'))->toAsn1())->shouldBeLike(new EqualityFilter('foo', 'bar'));
    }
}
