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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use PhpSpec\ObjectBehavior;

class ChangeSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(Change::TYPE_REPLACE, new Attribute('foo', 'bar'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Change::class);
    }

    function it_should_get_the_mod_type()
    {
        $this->getType()->shouldBeEqualTo(Change::TYPE_REPLACE);
    }

    function it_should_set_the_mod_type()
    {
        $this->setType(Change::TYPE_ADD)->getType()->shouldBeEqualTo(Change::TYPE_ADD);
    }

    function it_should_get_the_attribute()
    {
        $this->getAttribute()->shouldBeLike(new Attribute('foo', 'bar'));
    }

    function it_should_set_the_attribute()
    {
        $this->setAttribute(new Attribute('cn', 'foo'))->getAttribute()->shouldBeLike(new Attribute('cn', 'foo'));
    }

    function it_should_construct_a_reset_change()
    {
        $this->beConstructedThrough('reset', ['foo']);

        $this->getAttribute()->shouldBeLike(new Attribute('foo'));
        $this->getType()->shouldBeEqualTo(Change::TYPE_DELETE);
    }

    function it_should_construct_an_add_change()
    {
        $this->beConstructedThrough('add', ['foo', 'bar']);

        $this->getAttribute()->shouldBeLike(new Attribute('foo', 'bar'));
        $this->getType()->shouldBeEqualTo(Change::TYPE_ADD);
    }

    function it_should_construct_a_delete_change()
    {
        $this->beConstructedThrough('delete', ['foo', 'bar', 'foobar']);

        $this->getAttribute()->shouldBeLike(new Attribute('foo', 'bar', 'foobar'));
        $this->getType()->shouldBeEqualTo(Change::TYPE_DELETE);
    }

    function it_should_construct_a_replace_change()
    {
        $this->beConstructedThrough('replace', ['foo', 'bar']);

        $this->getAttribute()->shouldBeLike(new Attribute('foo', 'bar'));
        $this->getType()->shouldBeEqualTo(Change::TYPE_REPLACE);
    }
}
