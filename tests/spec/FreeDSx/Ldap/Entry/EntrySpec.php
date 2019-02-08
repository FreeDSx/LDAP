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
use FreeDSx\Ldap\Entry\Changes;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use PhpSpec\ObjectBehavior;

class EntrySpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new Dn('cn=foo,dc=example,dc=local'),
            new Attribute('cn', 'foo'),
            new Attribute('telephoneNumber', '123', '456'),
            new Attribute('cn;lang-en-us', 'bar'),
            new Attribute('member;range=0-*', 'dc=foo')
        );
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Entry::class);
    }

    function it_should_get_the_dn()
    {
        $this->getDn()->shouldBeLike(new Dn('cn=foo,dc=example,dc=local'));
    }

    function it_should_allow_being_constructed_with_a_string_dn()
    {
        $this->beConstructedWith('cn=foo,dc=example,dc=local');

        $this->getDn()->shouldBeLike(new Dn('cn=foo,dc=example,dc=local'));
    }

    function it_should_be_constructed_from_an_array_using_create()
    {
        $this->beConstructedThrough('create', ['cn=foobar,dc=example,dc=local', [
            'cn' => 'foobar',
            'telephoneNumber' => ['123', '456'],
        ]]);

        $this->getDn()->shouldBeLike(new Dn('cn=foobar,dc=example,dc=local'));
        $this->getAttributes()->shouldBeLike([
            new Attribute('cn', 'foobar'),
            new Attribute('telephoneNumber', '123', '456')
        ]);
    }

    function it_should_be_constructed_from_an_array_using_fromArray()
    {
        $this->beConstructedThrough('fromArray', ['cn=foobar,dc=example,dc=local', [
            'cn' => 'foobar',
            'telephoneNumber' => ['123', '456'],
        ]]);

        $this->getDn()->shouldBeLike(new Dn('cn=foobar,dc=example,dc=local'));
        $this->getAttributes()->shouldBeLike([
            new Attribute('cn', 'foobar'),
            new Attribute('telephoneNumber', '123', '456')
        ]);
    }

    function it_should_get_the_entry_as_an_associative_array()
    {
        $this->toArray()->shouldBeEqualTo([
            'cn' => ['foo'],
            'telephoneNumber' => [ '123', '456'],
            'cn;lang-en-us' => ['bar'],
            'member;range=0-*' => ['dc=foo']
        ]);
    }

    function it_should_get_the_count_as_the_amount_of_attributes_in_the_entry()
    {
        $this->count()->shouldBeEqualTo(4);
    }

    function it_should_have_a_string_representation_of_the_dn()
    {
        $this->__toString()->shouldBeEqualTo('cn=foo,dc=example,dc=local');
    }

    function it_should_return_null_for_an_attribute_that_doesnt_exist()
    {
        $this->get('foobar')->shouldBeNull();
    }

    function it_should_get_an_attribute_using_a_string()
    {
        $this->get('cN')->getName()->shouldBeEqualTo('cn');
    }

    function it_should_get_an_attribute_using_an_attribute()
    {
        $this->get(new Attribute('cn'))->getName()->shouldBeEqualTo('cn');
    }
    
    function it_should_get_an_attribute_with_options_using_only_the_name()
    {
        $this->get('cn')->getValues()->shouldBeEqualTo(['foo']);
    }
    
    function it_should_get_an_attribute_with_options_using_the_options()
    {
        $this->get('cn;lang-en-us')->getValues()->shouldBeLike(['bar']);
    }
    
    function it_should_not_get_an_attribute_with_the_same_name_if_the_requested_options_are_not_the_same()
    {
        $this->get('member;foo')->shouldBeNull();
    }
    
    function it_should_respect_the_strict_option_for_getting_an_attribute()
    {
        $this->get('member', true)->shouldBeNull();
        $this->get('member')->shouldBeAnInstanceOf(Attribute::class);
    }
    
    function it_should_reset_an_attribute_using_a_string()
    {
        $this->reset('cn')->get('cn', true)->shouldBeNull();
    }

    function it_should_remove_an_attribute_using_an_attribute()
    {
        $this->reset(new Attribute('cn'))->get('cn', true)->shouldBeNull();
    }

    function if_should_check_if_it_has_an_attribute_using_a_string()
    {
        $this->has('Cn')->shouldBeEqualTo(true);
        $this->has('bleh')->shouldBeEqualTo(false);
    }

    function it_should_check_if_it_has_an_attribute_using_an_attribute()
    {
        $this->has(new Attribute('cn'))->shouldBeEqualTo(true);
        $this->has(new Attribute('bleh'))->shouldBeEqualTo(false);
    }

    function it_should_get_an_attribute_through_the_magic_get()
    {
        $this->__get('CN')->getName()->shouldBeEqualTo('cn');
    }

    function it_should_get_null_on_an_attribute_that_doesnt_exist_through_the_magic_get()
    {
        $this->__get('foo')->shouldBeNull();
    }

    function it_should_set_an_attribute_through_the_magic_set()
    {
        $this->__set('foo', 'bar');
        $this->__set('bar', ['foo', 'bar']);

        $this->get('foo')->getValues()->shouldBeEqualTo(['bar']);
        $this->get('bar')->getValues()->shouldBeEqualTo(['foo', 'bar']);
    }

    function it_should_check_if_an_attribute_exists_through_the_magic_isset()
    {
        $this->__isset('CN')->shouldBeEqualTo(true);
        $this->__isset('foo')->shouldBeEqualTo(false);
    }

    function it_should_remove_a_variable_through_the_magic_unset()
    {
        $this->__unset('cn');

        $this->get('cn', true)->shouldBeNull();
    }

    function it_should_add_to_an_attributes_values_if_it_already_exists_while_adding()
    {
        $this->add('cn', 'bar');
        $this->get('cn')->getValues()->shouldBeEqualTo(['foo', 'bar']);

        $this->add(new Attribute('telephonenumber', '789'));
        $this->get('telephoneNumber')->getValues()->shouldBeEqualTo(['123', '456', '789']);

        $this->add('sn','smith');
        $this->get('sn')->getValues()->shouldBeLike(['smith']);
    }

    function it_should_remove_an_attributes_values_if_it_already_exists_when_deleting()
    {
        $this->remove('telephonenumber', '123');
        $this->get('telephoneNumber')->getValues()->shouldNotContain(['123']);

        $this->remove(new Attribute('telephonenumber', '456'));
        $this->get('telephoneNumber')->getValues()->shouldBeEqualTo([]);
    }

    function it_should_not_generate_a_delete_change_when_no_values_are_provided()
    {
        $this->remove('telephonenumber');
        $this->changes()->toArray()->shouldBeEqualTo([]);
    }

    function it_should_generate_a_delete_change_when_unsetting_an_attribute()
    {
        $this->__unset('telephonenumber');

        $this->changes()->toArray()[0]->getAttribute()->getName()->shouldBeEqualTo('telephonenumber');
        $this->changes()->toArray()[0]->getAttribute()->getValues()->shouldBeEqualTo([]);
        $this->changes()->toArray()[0]->getType()->shouldBeEqualTo(Change::TYPE_DELETE);

    }

    function it_should_generate_a_replace_change_when_setting_an_attribute()
    {
        $this->set('cn', 'foo');

        $this->changes()->toArray()[0]->getAttribute()->getName()->shouldBeEqualTo('cn');
        $this->changes()->toArray()[0]->getAttribute()->getValues()->shouldBeEqualTo(['foo']);
        $this->changes()->toArray()[0]->getType()->shouldBeEqualTo(Change::TYPE_REPLACE);
    }

    function it_should_generate_an_add_change_when_adding_an_attribute()
    {
        $this->add('sn', 'Smith');

        $this->changes()->toArray()[0]->getAttribute()->getName()->shouldBeEqualTo('sn');
        $this->changes()->toArray()[0]->getAttribute()->getValues()->shouldBeEqualTo(['Smith']);
        $this->changes()->toArray()[0]->getType()->shouldBeEqualTo(Change::TYPE_ADD);
    }

    function it_should_get_the_changes()
    {
        $this->changes()->shouldBeAnInstanceOf(Changes::class);
    }
}
