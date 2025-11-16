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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Changes;
use PHPUnit\Framework\TestCase;

class ChangesSpec extends TestCase
{
    private Changes $subject;

    protected function setUp(): void
    {
        $this->subject = new Changes(
            Change::replace(
                'foo',
                'bar',
            ),
            Change::delete('bar'),
        );
    }

    public function test_it_should_add_changes(): void
    {
        $change = Change::add('sn', 'foo');

        $this->subject->add($change);

        self::assertContains(
            $change,
            $this->subject->toArray(),
        );
    }

    public function test_it_should_remove_changes(): void
    {
        $change = Change::add('sn', 'foo');

        $this->subject->add($change);
        $this->subject->remove($change);

        self::assertNotContains(
            $change,
            $this->subject->toArray(),
        );
    }

    public function test_it_should_reset_changes(): void
    {
        $this->subject->reset();

        self::assertCount(
            0,
            $this->subject,
        );
    }

    public function test_it_should_get_the_count_of_changes(): void
    {
        self::assertCount(
            2,
            $this->subject,
        );
    }

    public function test_it_should_get_the_changes_as_an_array(): void
    {
        self::assertEquals(
            [
                Change::replace('foo', 'bar'),
                Change::delete('bar')
            ],
            $this->subject->toArray(),
        );
    }
}
