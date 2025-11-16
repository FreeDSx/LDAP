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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use PHPUnit\Framework\TestCase;

class EntriesTest extends TestCase
{
    private Entries $subject;

    protected function setUp(): void
    {
        $this->subject = new Entries(
            new Entry('foo'),
            new Entry('bar'),
        );
    }

    public function test_it_should_get_the_count(): void
    {
        self::assertCount(
            2,
            $this->subject,
        );
    }

    public function test_it_should_get_the_first_entry(): void
    {
        self::assertEquals(
            new Entry('foo'),
            $this->subject->first(),
        );
    }

    public function test_it_should_return_null_if_the_first_entry_does_not_exist(): void
    {
        $this->subject = new Entries();

        self::assertNull($this->subject->first());
    }

    public function test_it_should_get_the_last_entry(): void
    {
        self::assertEquals(
            new Entry('bar'),
            $this->subject->last(),
        );
    }

    public function test_it_should_return_null_if_the_last_entry_does_not_exist(): void
    {
        $this->subject = new Entries();

        self::assertNull($this->subject->last());
    }

    public function test_it_should_add_entries(): void
    {
        $this->subject->add(
            new Entry('cn=new'),
            new Entry('cn=another'),
        );

        self::assertCount(
            4,
            $this->subject,
        );
    }

    public function test_it_should_remove_entries(): void
    {
        $entry1 = new Entry('cn=new');
        $entry2 = new Entry('cn=another');

        $this->subject->add($entry1, $entry2);
        $this->subject->remove($entry1, $entry2);

        self::assertCount(
            2,
            $this->subject,
        );
    }

    public function test_it_should_not_remove_entries_if_they_dont_exist(): void
    {
        $this->subject->remove(new Entry('cn=meh'));

        self::assertCount(
            2,
            $this->subject,
        );
    }

    public function test_it_should_check_if_an_entry_object_is_in_the_collection(): void
    {
        $entry = new Entry('cn=meh');

        self::assertFalse($this->subject->has($entry));

        $this->subject->add($entry);

        self::assertTrue($this->subject->has($entry));
    }

    public function test_it_should_check_if_an_entry_is_in_the_collection_by_dn(): void
    {
        self::assertTrue($this->subject->has('foo'));
        self::assertFalse($this->subject->has('cn=meh'));
    }

    public function test_it_should_get_an_entry_by_dn(): void
    {
        self::assertEquals(
            new Entry('foo'),
            $this->subject->get('foo'),
        );
    }

    public function test_it_should_return_null_when_trying_to_get_an_entry_that_doesnt_exist(): void
    {
        self::assertNull($this->subject->get('meh'));
    }

    public function test_it_should_get_the_array_of_entries(): void
    {
        self::assertEquals(
            [
                new Entry('foo'),
                new Entry('bar')
            ],
            $this->subject->toArray(),
        );
    }
}
