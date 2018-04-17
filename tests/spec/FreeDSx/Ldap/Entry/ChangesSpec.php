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
    function let()
    {
        $this->beConstructedWith(Change::replace('foo', 'bar'), Change::delete('bar'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Changes::class);
    }

    function it_should_implement_countable()
    {
        $this->shouldImplement('\Countable');
    }

    function it_should_implement_iterable_aggregate()
    {
        $this->shouldImplement('\IteratorAggregate');
    }

    function it_should_add_changes()
    {
        $change = Change::add('sn', 'foo');
        $this->add($change);
        $this->toArray()->shouldContain($change);
    }

    function it_should_remove_changes()
    {
        $change = Change::add('sn', 'foo');
        $this->add($change);
        $this->remove($change);
        $this->toArray()->shouldNotContain($change);
    }

    function it_should_reset_changes()
    {
        $this->reset();
        $this->toArray()->shouldBeEqualTo([]);
    }

    function it_should_get_the_count_of_changes()
    {
        $this->count()->shouldBeEqualTo(2);
    }

    function it_should_get_the_changes_as_an_array()
    {
        $this->toArray()->shouldBeLike([
            Change::replace('foo', 'bar'),
            Change::delete('bar')
        ]);
    }
}
