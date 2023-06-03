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

namespace spec\FreeDSx\Ldap\Control\Sorting;

use FreeDSx\Ldap\Control\Sorting\SortKey;
use PhpSpec\ObjectBehavior;

class SortKeySpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('cn');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SortKey::class);
    }

    public function it_should_be_constructed_via_reverse_order(): void
    {
        $this->beConstructedWith('cn', true);

        $this->getUseReverseOrder()->shouldBeEqualTo(true);
    }

    public function it_should_be_constructed_ascending(): void
    {
        $this->beConstructedThrough('ascending', ['foo']);

        $this->getUseReverseOrder()->shouldBeEqualTo(false);
        $this->getAttribute()->shouldBeEqualTo('foo');
    }

    public function it_should_be_constructed_descending(): void
    {
        $this->beConstructedThrough('descending', ['foo']);

        $this->getUseReverseOrder()->shouldBeEqualTo(true);
        $this->getAttribute()->shouldBeEqualTo('foo');
    }

    public function it_should_not_use_reverse_order_by_default(): void
    {
        $this->getUseReverseOrder()->shouldBeEqualTo(false);
    }

    public function it_should_set_the_attribute_to_use(): void
    {
        $this->getAttribute()->shouldBeEqualTo('cn');
        $this->setAttribute('foo')->getAttribute()->shouldBeEqualTo('foo');
    }

    public function it_should_set_the_ordering_rule(): void
    {
        $this->getOrderingRule()->shouldBeNull();
        $this->setOrderingRule('foo')->getOrderingRule()->shouldBeEqualTo('foo');
    }

    public function it_should_set_whether_to_use_reverse_order(): void
    {
        $this->setUseReverseOrder(true);
        $this->getUseReverseOrder()->shouldBeEqualTo(true);
    }
}
