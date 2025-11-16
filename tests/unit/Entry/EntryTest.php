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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use PHPUnit\Framework\TestCase;

class EntryTest extends TestCase
{
    private Entry $subject;

    protected function setUp(): void
    {
        $this->subject = new Entry(
            new Dn('cn=foo,dc=example,dc=local'),
            new Attribute('cn', 'foo'),
            new Attribute('telephoneNumber', '123', '456'),
            new Attribute('cn;lang-en-us', 'bar'),
            new Attribute('member;range=0-*', 'dc=foo')
        );
    }

    public function test_it_should_get_the_dn(): void
    {
        self::assertEquals(
            new Dn('cn=foo,dc=example,dc=local'),
            $this->subject->getDn(),
        );
    }

    public function test_it_should_allow_being_constructed_with_a_string_dn(): void
    {
        $this->subject = new Entry('cn=foo,dc=example,dc=local');

        self::assertEquals(
            new Dn('cn=foo,dc=example,dc=local'),
            $this->subject->getDn(),
        );
    }

    public function test_it_should_be_constructed_from_an_array_using_create(): void
    {
        $this->subject = Entry::create(
            'cn=foobar,dc=example,dc=local',
            [
                'cn' => 'foobar',
                'telephoneNumber' => ['123', '456'],
            ]
        );

        self::assertEquals(
            new Dn('cn=foobar,dc=example,dc=local'),
            $this->subject->getDn(),
        );
        self::assertEquals(
            [
                new Attribute('cn', 'foobar'),
                new Attribute('telephoneNumber', '123', '456')
            ],
            $this->subject->getAttributes(),
        );
    }

    public function test_it_should_be_constructed_from_an_array_using_fromArray(): void
    {
        $this->subject = Entry::fromArray(
            'cn=foobar,dc=example,dc=local',
            [
                'cn' => 'foobar',
                'telephoneNumber' => ['123', '456'],
            ]
        );

        self::assertEquals(
            new Dn('cn=foobar,dc=example,dc=local'),
            $this->subject->getDn(),
        );
        self::assertEquals(
            [
                new Attribute('cn', 'foobar'),
                new Attribute('telephoneNumber', '123', '456')
            ],
            $this->subject->getAttributes(),
        );
    }

    public function test_it_should_be_constructed_from_an_array_using_fromArray_when_not_all_data_are_strings(): void
    {
        $this->subject = Entry::fromArray(
            'cn=foobar,dc=example,dc=local',
            [
                'cn' => 'foobar',
                'telephoneNumber' => [123, 456],
                'is_bad_idea' => true,
            ]
        );

        self::assertEquals(
            new Dn('cn=foobar,dc=example,dc=local'),
            $this->subject->getDn(),
        );
        self::assertEquals(
            [
                new Attribute('cn', 'foobar'),
                new Attribute('telephoneNumber', '123', '456'),
                new Attribute('is_bad_idea', '1')
            ],
            $this->subject->getAttributes(),
        );
    }

    public function test_it_should_get_the_entry_as_an_associative_array(): void
    {
        self::assertSame(
            [
                'cn' => ['foo'],
                'telephoneNumber' => [ '123', '456'],
                'cn;lang-en-us' => ['bar'],
                'member;range=0-*' => ['dc=foo']
            ],
            $this->subject->toArray(),
        );
    }

    public function test_it_should_get_the_count_as_the_amount_of_attributes_in_the_entry(): void
    {
        self::assertCount(
            4,
            $this->subject
        );
    }

    public function test_it_should_have_a_string_representation_of_the_dn(): void
    {
        self::assertSame(
            'cn=foo,dc=example,dc=local',
            (string) $this->subject->getDn(),
        );
    }

    public function test_it_should_return_null_for_an_attribute_that_doesnt_exist(): void
    {
        self::assertNull($this->subject->get('foobar'));
    }

    public function test_it_should_get_an_attribute_using_a_string(): void
    {
        self::assertSame(
            'cn',
            $this->subject->get('cN')?->getName(),
        );
    }

    public function test_it_should_get_an_attribute_using_an_attribute(): void
    {
        self::assertSame(
            'cn',
            $this->subject->get(new Attribute('cn'))?->getName(),
        );
    }
    
    public function test_it_should_get_an_attribute_with_options_using_only_the_name(): void
    {
        self::assertSame(
            ['foo'],
            $this->subject->get('cn')?->getValues(),
        );
    }
    
    public function test_it_should_get_an_attribute_with_options_using_the_options(): void
    {
        self::assertSame(
            ['bar'],
            $this->subject->get('cn;lang-en-us')?->getValues()
        );
    }
    
    public function test_it_should_not_get_an_attribute_with_the_same_name_if_the_requested_options_are_not_the_same(): void
    {
        self::assertNull($this->subject->get('member;foo'));
    }
    
    public function test_it_should_respect_the_strict_option_for_getting_an_attribute(): void
    {
        self::assertNull($this->subject->get('member', true));
        self::assertInstanceOf(
            Attribute::class,
            $this->subject->get('member')
        );
    }
    
    public function test_it_should_reset_an_attribute_using_a_string(): void
    {
        $this->subject->reset('cn');

        self::assertNull($this->subject->get('cn', true));
    }

    public function test_it_should_remove_an_attribute_using_an_attribute(): void
    {
        $this->subject->reset(new Attribute('cn'));

        self::assertNull($this->subject->get('cn', true));
    }

    public function if_should_check_if_it_has_an_attribute_using_a_string()
    {
        self::assertTrue($this->subject->has('Cn'));
        self::assertFalse($this->subject->has('bleh'));
    }

    public function test_it_should_check_if_it_has_an_attribute_using_an_attribute(): void
    {
        self::assertTrue($this->subject->has(new Attribute('cn')));
        self::assertFalse($this->subject->has(new Attribute('bleh')));
    }

    public function test_it_should_get_an_attribute_through_the_magic_get(): void
    {
        self::assertSame(
            'cn',
            $this->subject->__get('CN')?->getName(),
        );
    }

    public function test_it_should_get_null_on_an_attribute_that_doesnt_exist_through_the_magic_get(): void
    {
        self::assertNull($this->subject->__get('foo'));
    }

    public function test_it_should_set_an_attribute_through_the_magic_set(): void
    {
        $this->subject->__set('foo', 'bar');
        $this->subject->__set('bar', ['foo', 'bar']);

        self::assertSame(
            ['bar'],
            $this->subject->get('foo')?->getValues(),
        );
        self::assertSame(
            ['foo', 'bar'],
            $this->subject->get('bar')?->getValues(),
        );
    }

    public function test_it_should_check_if_an_attribute_exists_through_the_magic_isset(): void
    {
        self::assertTrue($this->subject->__isset('CN'));
        self::assertFalse($this->subject->__isset('foo'));
    }

    public function test_it_should_remove_a_variable_through_the_magic_unset(): void
    {
        $this->subject->__unset('cn');

        self::assertNull($this->subject->get('cn', true));
    }

    public function test_it_should_add_to_an_attributes_values_if_it_already_exists_while_adding(): void
    {
        $this->subject->add('cn', 'bar');

        self::assertSame(
            ['foo', 'bar'],
            $this->subject->get('cn')?->getValues(),
        );

        $this->subject->add(new Attribute('telephonenumber', '789'));

        self::assertSame(
            ['123', '456', '789'],
            $this->subject->get('telephoneNumber')?->getValues(),
        );

        $this->subject->add('sn', 'smith');

        self::assertSame(
            ['smith'],
            $this->subject->get('sn')?->getValues(),
        );
    }

    public function test_it_should_remove_an_attributes_values_if_it_already_exists_when_deleting(): void
    {
        $this->subject->remove('telephonenumber', '123');

        self::assertNotContains(
            '123',
            (array) $this->subject->get('telephoneNumber')?->getValues()
        );

        $this->subject->remove(new Attribute('telephonenumber', '456'));

        self::assertSame(
            [],
            $this->subject->get('telephoneNumber')?->getValues(),
        );
    }

    public function test_it_should_not_generate_a_delete_change_when_no_values_are_provided(): void
    {
        $this->subject->remove('telephonenumber');

        self::assertSame(
            [],
            $this->subject->changes()->toArray(),
        );
    }

    public function test_it_should_generate_a_delete_change_when_unsetting_an_attribute(): void
    {
        $this->subject->__unset('telephonenumber');

        $change = $this->subject->changes()->toArray()[0];

        self::assertNotNull($change);
        self::assertSame(
            'telephonenumber',
            $change->getAttribute()->getName(),
        );
        self::assertSame(
            [],
            $change->getAttribute()->getValues(),
        );
        self::assertSame(
            Change::TYPE_DELETE,
            $change->getType(),
        );
    }

    public function test_it_should_generate_a_replace_change_when_setting_an_attribute(): void
    {
        $this->subject->set('cn', 'foo');

        $change = $this->subject->changes()->toArray()[0];

        self::assertNotNull($change);
        self::assertSame(
            'cn',
            $change->getAttribute()->getName(),
        );
        self::assertSame(
            ['foo'],
            $change->getAttribute()->getValues(),
        );
        self::assertSame(
            Change::TYPE_REPLACE,
            $change->getType(),
        );
    }

    public function test_it_should_generate_an_add_change_when_adding_an_attribute(): void
    {
        $this->subject->add('sn', 'Smith');

        $change = $this->subject->changes()->toArray()[0];

        self::assertNotNull($change);
        self::assertSame(
            'sn',
            $change->getAttribute()->getName(),
        );
        self::assertSame(
            ['Smith'],
            $change->getAttribute()->getValues(),
        );
        self::assertSame(
            Change::TYPE_ADD,
            $change->getType(),
        );
    }
}
