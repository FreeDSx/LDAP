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

namespace Tests\Unit\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use PHPUnit\Framework\TestCase;

class ChangeTest extends TestCase
{
    private Change $subject;

    protected function setUp(): void
    {
        $this->subject = new Change(
            Change::TYPE_REPLACE,
            new Attribute('foo', 'bar')
        );
    }

    public function test_it_should_get_the_mod_type(): void
    {
        self::assertSame(
            Change::TYPE_REPLACE,
            $this->subject->getType(),
        );
    }

    public function test_it_should_set_the_mod_type(): void
    {
        $this->subject->setType(Change::TYPE_ADD);

        self::assertSame(
            Change::TYPE_ADD,
            $this->subject->getType(),
        );
    }

    public function test_it_should_get_the_attribute(): void
    {
        self::assertEquals(
            new Attribute('foo', 'bar'),
            $this->subject->getAttribute(),
        );
    }

    public function test_it_should_set_the_attribute(): void
    {
        $this->subject->setAttribute(new Attribute(
            'foo',
            'bar'
        ));

        self::assertEquals(
            new Attribute('foo', 'bar'),
            $this->subject->getAttribute(),
        );
    }

    public function test_it_should_construct_a_reset_change(): void
    {
        $this->subject = Change::reset('foo');

        self::assertEquals(
            new Attribute('foo'),
            $this->subject->getAttribute(),
        );
        self::assertSame(
            Change::TYPE_DELETE,
            $this->subject->getType(),
        );
    }

    public function test_it_should_construct_an_add_change(): void
    {
        $this->subject = Change::add('foo', 'bar');

        self::assertEquals(
            new Attribute('foo', 'bar'),
            $this->subject->getAttribute(),
        );
        self::assertSame(
            Change::TYPE_ADD,
            $this->subject->getType(),
        );
    }

    public function test_it_should_construct_a_delete_change(): void
    {
        $this->subject = Change::delete('foo', 'bar', 'foobar');

        self::assertEquals(
            new Attribute('foo', 'bar', 'foobar'),
            $this->subject->getAttribute(),
        );
        self::assertSame(
            Change::TYPE_DELETE,
            $this->subject->getType(),
        );
    }

    public function test_it_should_construct_a_replace_change(): void
    {
        $this->subject = Change::replace('foo', 'bar');

        self::assertEquals(
            new Attribute('foo', 'bar'),
            $this->subject->getAttribute(),
        );
        self::assertSame(
            Change::TYPE_REPLACE,
            $this->subject->getType(),
        );
    }

    public function test_it_should_check_whether_it_is_an_add(): void
    {
        self::assertFalse($this->subject->isAdd());

        $this->subject->setType(Change::TYPE_ADD);

        self::assertTrue($this->subject->isAdd());
    }

    public function test_it_should_check_whether_it_is_a_delete(): void
    {
        self::assertFalse($this->subject->isDelete());

        $this->subject->setType(Change::TYPE_DELETE);

        self::assertTrue($this->subject->isDelete());
    }

    public function test_it_should_check_whether_it_is_a_replace(): void
    {
        $this->subject->setType(Change::TYPE_REPLACE);

        self::assertTrue($this->subject->isReplace());
    }

    public function test_it_should_check_whether_it_is_a_reset(): void
    {
        self::assertFalse($this->subject->isReset());

        $this->subject->setType(Change::TYPE_DELETE);

        self::assertFalse($this->subject->isReset());

        $this->subject->setAttribute(new Attribute('foo'));

        self::assertTrue($this->subject->isReset());
    }
}
