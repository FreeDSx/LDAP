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

namespace Tests\Unit\FreeDSx\Ldap\Control;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use PHPUnit\Framework\TestCase;

class ControlBagTest extends TestCase
{
    private ControlBag $subject;

    protected function setUp(): void
    {
        $this->subject = new ControlBag(
            new Control('foo'),
            new Control('bar'),
        );
    }

    public function test_it_should_get_the_control_count(): void
    {
        self::assertCount(
            2,
            $this->subject,
        );
    }

    public function test_it_should_get_a_control_by_string(): void
    {
        self::assertEquals(
            new Control('foo'),
            $this->subject->get('foo'),
        );
    }

    public function test_it_should_return_null_on_a_control_that_doesnt_exist(): void
    {
        self::assertNull($this->subject->get('foobar'));
    }

    public function test_it_should_add_a_control(): void
    {
        $this->subject->add(new Control('foobar'));

        self::assertTrue($this->subject->has('foobar'));;
    }

    public function test_it_should_check_if_a_control_exists_with_has(): void
    {
        self::assertFalse($this->subject->has('foobar'));
        self::assertTrue($this->subject->has('bar'));
    }

    public function test_it_should_check_if_a_control_exists_by_an_object_check(): void
    {
        $foobar = new Control('foobar');

        self::assertFalse($this->subject->has($foobar));

        $this->subject->add($foobar);

        self::assertTrue($this->subject->has($foobar));
    }

    public function test_it_should_remove_a_control_by_string(): void
    {
        $this->subject->remove('foo');

        self::assertFalse($this->subject->has('foo'));
    }

    public function test_it_should_remove_a_control_by_object(): void
    {
        $foobar = new Control('foobar');
        $this->subject->add($foobar);

        self::assertTrue($this->subject->has($foobar));

        $this->subject->remove($foobar);

        self::assertFalse($this->subject->has($foobar));
    }

    public function test_it_should_get_the_controls_as_an_array(): void
    {
        self::assertEquals(
            [
                new Control('foo'),
                new Control('bar'),
            ],
            $this->subject->toArray(),
        );
    }

    public function test_it_should_reset_the_controls(): void
    {
        $this->subject->reset();

        self::assertCount(
            0,
            $this->subject,
        );
    }

    public function test_it_should_get_a_control_by_its_class_name(): void
    {
        $this->subject->add(new SyncRequestControl());

        self::assertInstanceOf(
            SyncRequestControl::class,
            $this->subject->getByClass(SyncRequestControl::class),
        );
    }

    public function test_it_should_return_null_if_a_control_by_its_class_name_does_not_exist(): void
    {
        self::assertNull($this->subject->get(SyncRequestControl::class));
    }
}
