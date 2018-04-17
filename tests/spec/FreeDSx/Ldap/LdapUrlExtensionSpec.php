<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap;

use FreeDSx\Ldap\LdapUrlExtension;
use PhpSpec\ObjectBehavior;

class LdapUrlExtensionSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LdapUrlExtension::class);
    }

    function it_should_get_the_extension_name()
    {
        $this->getName()->shouldBeEqualTo('foo');
        $this->setName('bar')->getName()->shouldBeEqualTo('bar');
    }

    function it_should_get_the_extension_value()
    {
        $this->getValue()->shouldBeNull();
        $this->setValue('bar')->getValue()->shouldBeEqualTo('bar');
    }

    function it_should_get_the_criticality()
    {
        $this->getIsCritical()->shouldBeEqualTo(false);
        $this->setIsCritical(true)->getIsCritical()->shouldBeEqualTo(true);
    }

    function it_should_parse_an_extension_with_only_a_name()
    {
        $this::parse('foo')->shouldBeLike(new LdapUrlExtension('foo'));
    }

    function it_should_generate_a_string_extension_with_only_a_name()
    {
        $this->toString()->shouldBeEqualTo('foo');
    }

    function it_should_parse_an_extension_with_a_criticality()
    {
        $this::parse('!foo')->shouldBeLike(new LdapUrlExtension('foo', null, true));
    }

    function it_should_generate_a_string_extension_with_a_criticality()
    {
        $this->setIsCritical(true);

        $this->toString()->shouldBeEqualTo('!foo');
    }

    function it_should_parse_an_extension_with_a_value()
    {
        $this::parse('foo=bar')->shouldBeLike(new LdapUrlExtension('foo', 'bar'));
    }

    function it_should_generate_a_string_extension_with_a_value()
    {
        $this->setValue('bar');

        $this->toString()->shouldBeEqualTo('foo=bar');
    }

    function it_should_parse_an_extension_and_decode_it_if_needed()
    {
        $this::parse('e-bindname=cn=Manager%2cdc=example%2cdc=com')->shouldBeLike(new LdapUrlExtension('e-bindname', 'cn=Manager,dc=example,dc=com'));
    }

    function it_should_generate_a_string_extension_and_encode_it_if_needed()
    {
        $this->beConstructedWith('e-bindname', 'cn=Manager,dc=example,dc=com');

        $this->toString()->shouldBeEqualTo('e-bindname=cn=Manager%2cdc=example%2cdc=com');
    }
}
