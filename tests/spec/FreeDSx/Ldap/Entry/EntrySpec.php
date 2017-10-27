<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use PhpSpec\ObjectBehavior;

class EntrySpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new Dn('cn=foo,dc=example,dc=local'),
            new Attribute('cn', 'foo'),
            new Attribute('telephoneNumber', '123', '456')
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

    function it_should_be_constructed_from_an_array()
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

    function it_should_get_the_entry_as_an_associative_array()
    {
        $this->toArray()->shouldBeEqualTo([
            'cn' => ['foo'],
            'telephoneNumber' => [ '123', '456'],
        ]);
    }

    function it_should_get_the_count_as_the_amount_of_attributes_in_the_entry()
    {
        $this->count()->shouldBeEqualTo(2);
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

    function it_should_remove_an_attribute_using_a_string()
    {
        $this->remove('cn')->get('cn')->shouldBeNull();
    }

    function it_should_remove_an_attribute_using_an_attribute()
    {
        $this->remove(new Attribute('cn'))->get('cn')->shouldBeNull();
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
}
