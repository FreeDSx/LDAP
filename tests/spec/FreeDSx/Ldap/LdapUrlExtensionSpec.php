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
    public function let(): void
    {
        $this->beConstructedWith('foo');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(LdapUrlExtension::class);
    }

    public function it_should_get_the_extension_name(): void
    {
        $this->getName()->shouldBeEqualTo('foo');
        $this->setName('bar')->getName()->shouldBeEqualTo('bar');
    }

    public function it_should_get_the_extension_value(): void
    {
        $this->getValue()->shouldBeNull();
        $this->setValue('bar')->getValue()->shouldBeEqualTo('bar');
    }

    public function it_should_get_the_criticality(): void
    {
        $this->getIsCritical()->shouldBeEqualTo(false);
        $this->setIsCritical(true)->getIsCritical()->shouldBeEqualTo(true);
    }

    public function it_should_parse_an_extension_with_only_a_name(): void
    {
        $this::parse('foo')->shouldBeLike(new LdapUrlExtension('foo'));
    }

    public function it_should_generate_a_string_extension_with_only_a_name(): void
    {
        $this->toString()->shouldBeEqualTo('foo');
    }

    public function it_should_parse_an_extension_with_a_criticality(): void
    {
        $this::parse('!foo')->shouldBeLike(new LdapUrlExtension('foo', null, true));
    }

    public function it_should_generate_a_string_extension_with_a_criticality(): void
    {
        $this->setIsCritical(true);

        $this->toString()->shouldBeEqualTo('!foo');
    }

    public function it_should_parse_an_extension_with_a_value(): void
    {
        $this::parse('foo=bar')->shouldBeLike(new LdapUrlExtension('foo', 'bar'));
    }

    public function it_should_generate_a_string_extension_with_a_value(): void
    {
        $this->setValue('bar');

        $this->toString()->shouldBeEqualTo('foo=bar');
    }

    public function it_should_parse_an_extension_and_decode_it_if_needed(): void
    {
        $this::parse('e-bindname=cn=Manager%2cdc=example%2cdc=com')->shouldBeLike(new LdapUrlExtension('e-bindname', 'cn=Manager,dc=example,dc=com'));
    }

    public function it_should_generate_a_string_extension_and_encode_it_if_needed(): void
    {
        $this->beConstructedWith('e-bindname', 'cn=Manager,dc=example,dc=com');

        $this->toString()->shouldBeEqualTo('e-bindname=cn=Manager%2cdc=example%2cdc=com');
    }
}
