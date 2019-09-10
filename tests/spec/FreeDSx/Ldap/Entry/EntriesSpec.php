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
use FreeDSx\Ldap\Exception\InvalidArgumentException;
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

    function it_should_add_entries()
    {
        $this->add(new Entry('cn=new'), new Entry('cn=another'));
        $this->count()->shouldBeEqualTo(4);
    }

    function it_should_remove_entries()
    {
        $entry1 = new Entry('cn=new');
        $entry2 = new Entry('cn=another');
        $this->add($entry1, $entry2);
        $this->remove($entry1, $entry2);
        $this->count()->shouldBeEqualTo(2);
    }

    function it_should_not_remove_entries_if_they_dont_exist()
    {
        $this->remove(new Entry('cn=meh'));
        $this->count()->shouldBeEqualTo(2);
    }

    function it_should_check_if_an_entry_object_is_in_the_collection()
    {
        $entry = new Entry('cn=meh');
        $this->has($entry)->shouldBeEqualTo(false);
        $this->add($entry);
        $this->has($entry)->shouldBeEqualTo(true);

    }

    function it_should_check_if_an_entry_is_in_the_collection_by_dn()
    {
        $this->has('foo')->shouldBeEqualTo(true);
        $this->has('cn=meh')->shouldBeEqualTo(false);
    }

    function it_should_get_an_entry_by_dn()
    {
        $this->get('foo')->shouldBeLike(new Entry('foo'));
    }

    function it_should_return_null_when_trying_to_get_an_entry_that_doesnt_exist()
    {
        $this->get('meh')->shouldBeNull();
    }

    function it_should_get_the_array_of_entries()
    {
        $this->toArray()->shouldBeLike([
            new Entry('foo'),
            new Entry('bar')
        ]);
    }
}
