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
    public function let(): void
    {
        $this->beConstructedWith(Change::TYPE_REPLACE, new Attribute('foo', 'bar'));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(Change::class);
    }

    public function it_should_get_the_mod_type(): void
    {
        $this->getType()->shouldBeEqualTo(Change::TYPE_REPLACE);
    }

    public function it_should_set_the_mod_type(): void
    {
        $this->setType(Change::TYPE_ADD)->getType()->shouldBeEqualTo(Change::TYPE_ADD);
    }

    public function it_should_get_the_attribute(): void
    {
        $this->getAttribute()->shouldBeLike(new Attribute('foo', 'bar'));
    }

    public function it_should_set_the_attribute(): void
    {
        $this->setAttribute(new Attribute('cn', 'foo'))->getAttribute()->shouldBeLike(new Attribute('cn', 'foo'));
    }

    public function it_should_construct_a_reset_change(): void
    {
        $this->beConstructedThrough('reset', ['foo']);

        $this->getAttribute()->shouldBeLike(new Attribute('foo'));
        $this->getType()->shouldBeEqualTo(Change::TYPE_DELETE);
    }

    public function it_should_construct_an_add_change(): void
    {
        $this->beConstructedThrough('add', ['foo', 'bar']);

        $this->getAttribute()->shouldBeLike(new Attribute('foo', 'bar'));
        $this->getType()->shouldBeEqualTo(Change::TYPE_ADD);
    }

    public function it_should_construct_a_delete_change(): void
    {
        $this->beConstructedThrough('delete', ['foo', 'bar', 'foobar']);

        $this->getAttribute()->shouldBeLike(new Attribute('foo', 'bar', 'foobar'));
        $this->getType()->shouldBeEqualTo(Change::TYPE_DELETE);
    }

    public function it_should_construct_a_replace_change(): void
    {
        $this->beConstructedThrough('replace', ['foo', 'bar']);

        $this->getAttribute()->shouldBeLike(new Attribute('foo', 'bar'));
        $this->getType()->shouldBeEqualTo(Change::TYPE_REPLACE);
    }

    public function it_should_check_whether_it_is_an_add(): void
    {
        $this->isAdd()->shouldBeEqualTo(false);
        $this->setType(Change::TYPE_ADD);
        $this->isAdd()->shouldBeEqualTo(true);
    }

    public function it_should_check_whether_it_is_a_delete(): void
    {
        $this->isDelete()->shouldBeEqualTo(false);
        $this->setType(Change::TYPE_DELETE);
        $this->isDelete()->shouldBeEqualTo(true);
        $this->setAttribute(new Attribute('foo'));
        $this->isDelete()->shouldBeEqualTo(false);
    }

    public function it_should_check_whether_it_is_a_replace(): void
    {
        $this->isReplace()->shouldBeEqualTo(true);
        $this->setType(Change::TYPE_ADD);
        $this->isReplace()->shouldBeEqualTo(false);
    }

    public function it_should_check_whether_it_is_a_reset(): void
    {
        $this->isReset()->shouldBeEqualTo(false);
        $this->setType(Change::TYPE_DELETE);
        $this->isReset()->shouldBeEqualTo(false);
        $this->setAttribute(new Attribute('foo'));
        $this->isReset()->shouldBeEqualTo(true);
    }
}
