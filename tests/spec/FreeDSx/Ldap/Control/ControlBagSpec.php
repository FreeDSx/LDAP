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

namespace spec\FreeDSx\Ldap\Control;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use PhpSpec\ObjectBehavior;

class ControlBagSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(new Control('foo'), new Control('bar'));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ControlBag::class);
    }

    public function it_should_implement_iterator_aggregate(): void
    {
        $this->shouldImplement('\IteratorAggregate');
    }

    public function it_should_implement_countable(): void
    {
        $this->shouldImplement('\Countable');
    }

    public function it_should_get_the_control_count(): void
    {
        $this->count()->shouldBeEqualTo(2);
    }

    public function it_should_get_a_control_by_string(): void
    {
        $this->get('foo')->shouldBeLike(new Control('foo'));
    }

    public function it_should_return_null_on_a_control_that_doesnt_exist(): void
    {
        $this->get('foobar')->shouldBeNull();
    }

    public function it_should_add_a_control(): void
    {
        $this->add(new Control('foobar'));

        $this->has('foobar')->shouldBeEqualTo(true);
    }

    public function it_should_check_if_a_control_exists_with_has(): void
    {
        $this->has('bar')->shouldBeEqualTo(true);
        $this->has('foobar')->shouldBeEqualTo(false);
    }

    public function it_should_check_if_a_control_exists_by_an_object_check(): void
    {
        $foobar = new Control('foobar');

        $this->has($foobar)->shouldBeEqualTo(false);
        $this->add($foobar);
        $this->has($foobar)->shouldBeEqualTo(true);
    }

    public function it_should_remove_a_control_by_string(): void
    {
        $this->remove('foo');

        $this->has('foo')->shouldBeEqualTo(false);
    }

    public function it_should_remove_a_control_by_object(): void
    {
        $foobar = new Control('foobar');
        $this->add($foobar);
        $this->has($foobar)->shouldBeEqualTo(true);

        $this->remove($foobar);
        $this->has($foobar)->shouldBeEqualTo(false);
    }

    public function it_should_get_the_controls_as_an_array(): void
    {
        $this->toArray()->shouldBeLike([new Control('foo'), new Control('bar')]);
    }

    public function it_should_reset_the_controls(): void
    {
        $this->reset();

        $this->toArray()->shouldBeEqualTo([]);
    }

    public function it_should_get_a_control_by_its_class_name(): void
    {
        $this->add(new SyncRequestControl());

        $this->getByClass(SyncRequestControl::class)
            ->shouldBeAnInstanceOf(SyncRequestControl::class);
    }

    public function it_should_return_null_if_a_control_by_its_class_name_does_not_exist(): void
    {
        $this->getByClass(SyncRequestControl::class)
            ->shouldBeNull();
    }
}
