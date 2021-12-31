<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use PhpSpec\ObjectBehavior;

class ControlBagSpec extends ObjectBehavior
{
    public function let()
    {
        $this->beConstructedWith(new Control('foo'), new Control('bar'));
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(ControlBag::class);
    }

    public function it_should_implement_iterator_aggregate()
    {
        $this->shouldImplement('\IteratorAggregate');
    }

    public function it_should_implement_countable()
    {
        $this->shouldImplement('\Countable');
    }

    public function it_should_get_the_control_count()
    {
        $this->count()->shouldBeEqualTo(2);
    }

    public function it_should_get_a_control_by_string()
    {
        $this->get('foo')->shouldBeLike(new Control('foo'));
    }

    public function it_should_return_null_on_a_control_that_doesnt_exist()
    {
        $this->get('foobar')->shouldBeNull();
    }

    public function it_should_add_a_control()
    {
        $this->add(new Control('foobar'));

        $this->has('foobar')->shouldBeEqualTo(true);
    }

    public function it_should_check_if_a_control_exists_with_has()
    {
        $this->has('bar')->shouldBeEqualTo(true);
        $this->has('foobar')->shouldBeEqualTo(false);
    }

    public function it_should_check_if_a_control_exists_by_an_object_check()
    {
        $foobar = new Control('foobar');

        $this->has($foobar)->shouldBeEqualTo(false);
        $this->add($foobar);
        $this->has($foobar)->shouldBeEqualTo(true);
    }

    public function it_should_remove_a_control_by_string()
    {
        $this->remove('foo');

        $this->has('foo')->shouldBeEqualTo(false);
    }

    public function it_should_remove_a_control_by_object()
    {
        $foobar = new Control('foobar');
        $this->add($foobar);
        $this->has($foobar)->shouldBeEqualTo(true);

        $this->remove($foobar);
        $this->has($foobar)->shouldBeEqualTo(false);
    }

    public function it_should_get_the_controls_as_an_array()
    {
        $this->toArray()->shouldBeLike([new Control('foo'), new Control('bar')]);
    }

    public function it_should_reset_the_controls()
    {
        $this->reset();

        $this->toArray()->shouldBeEqualTo([]);
    }
}
