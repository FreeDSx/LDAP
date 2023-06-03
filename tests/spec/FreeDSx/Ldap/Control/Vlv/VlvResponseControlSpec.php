<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control\Vlv;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class VlvResponseControlSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(10, 9, 0);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(VlvResponseControl::class);
    }

    public function it_should_get_the_offset(): void
    {
        $this->getOffset()->shouldBeEqualTo(10);
    }

    public function it_should_get_the_count(): void
    {
        $this->getCount()->shouldBeEqualTo(9);
    }

    public function it_should_get_the_context_id(): void
    {
        $this->getContextId()->shouldBeNull();
    }

    public function it_should_get_the_result(): void
    {
        $this->getResult()->shouldBeEqualTo(0);
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $this::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_VLV_RESPONSE),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(1),
                Asn1::integer(300),
                Asn1::enumerated(0),
                Asn1::octetString('foo')
            )))
        ))->setValue(null)->shouldBeLike(new VlvResponseControl(1, 300, 0, 'foo'));
    }
}
