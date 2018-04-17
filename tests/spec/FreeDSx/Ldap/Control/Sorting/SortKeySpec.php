<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control\Sorting;

use FreeDSx\Ldap\Control\Sorting\SortKey;
use PhpSpec\ObjectBehavior;

class SortKeySpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('cn');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SortKey::class);
    }

    function it_should_be_constructed_via_reverse_order()
    {
        $this->beConstructedWith('cn', true);

        $this->getUseReverseOrder()->shouldBeEqualTo(true);

    }

    function it_should_be_constructed_ascending()
    {
        $this->beConstructedThrough('ascending', ['foo']);

        $this->getUseReverseOrder()->shouldBeEqualTo(false);
        $this->getAttribute()->shouldBeEqualTo('foo');
    }

    function it_should_be_constructed_descending()
    {
        $this->beConstructedThrough('descending', ['foo']);

        $this->getUseReverseOrder()->shouldBeEqualTo(true);
        $this->getAttribute()->shouldBeEqualTo('foo');
    }

    function it_should_not_use_reverse_order_by_default()
    {
        $this->getUseReverseOrder()->shouldBeEqualTo(false);
    }

    function it_should_set_the_attribute_to_use()
    {
        $this->getAttribute()->shouldBeEqualTo('cn');
        $this->setAttribute('foo')->getAttribute()->shouldBeEqualTo('foo');
    }

    function it_should_set_the_ordering_rule()
    {
        $this->getOrderingRule()->shouldBeNull();
        $this->setOrderingRule('foo')->getOrderingRule()->shouldBeEqualTo('foo');
    }

    function it_should_set_whether_to_use_reverse_order()
    {
        $this->setUseReverseOrder(true);
        $this->getUseReverseOrder()->shouldBeEqualTo(true);
    }
}
