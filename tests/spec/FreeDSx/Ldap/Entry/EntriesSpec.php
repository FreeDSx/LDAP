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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use PhpSpec\ObjectBehavior;

class EntriesSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new Entry('foo'), new Entry('bar'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Entries::class);
    }

    function it_should_implement_countable()
    {
        $this->shouldImplement('\Countable');
    }

    function it_should_implement_iterator_aggregate()
    {
        $this->shouldImplement('\IteratorAggregate');
    }

    function it_should_get_the_count()
    {
        $this->count()->shouldBeEqualTo(2);
    }

    function it_should_get_the_first_entry()
    {
        $this->first()->shouldBeLike(new Entry('foo'));
    }

    function it_should_return_null_if_the_first_entry_does_not_exist()
    {
        $this->beConstructedWith(...[]);

        $this->first()->shouldBeNull();
    }

    function it_should_get_the_last_entry()
    {
        $this->last()->shouldBeLike(new Entry('bar'));
    }

    function it_should_return_null_if_the_last_entry_does_not_exist()
    {
        $this->beConstructedWith(...[]);

        $this->last()->shouldBeNull();
    }

    function it_should_get_the_array_of_entries()
    {
        $this->toArray()->shouldBeLike([
            new Entry('foo'),
            new Entry('bar')
        ]);
    }
}
