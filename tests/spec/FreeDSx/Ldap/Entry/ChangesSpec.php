<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Changes;
use PhpSpec\ObjectBehavior;

class ChangesSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(Change::replace('foo', 'bar'), Change::delete('bar'));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(Changes::class);
    }

    public function it_should_implement_countable(): void
    {
        $this->shouldImplement('\Countable');
    }

    public function it_should_implement_iterable_aggregate(): void
    {
        $this->shouldImplement('\IteratorAggregate');
    }

    public function it_should_add_changes(): void
    {
        $change = Change::add('sn', 'foo');
        $this->add($change);
        $this->toArray()->shouldContain($change);
    }

    public function it_should_remove_changes(): void
    {
        $change = Change::add('sn', 'foo');
        $this->add($change);
        $this->remove($change);
        $this->toArray()->shouldNotContain($change);
    }

    public function it_should_reset_changes(): void
    {
        $this->reset();
        $this->toArray()->shouldBeEqualTo([]);
    }

    public function it_should_get_the_count_of_changes(): void
    {
        $this->count()->shouldBeEqualTo(2);
    }

    public function it_should_get_the_changes_as_an_array(): void
    {
        $this->toArray()->shouldBeLike([
            Change::replace('foo', 'bar'),
            Change::delete('bar')
        ]);
    }
}
