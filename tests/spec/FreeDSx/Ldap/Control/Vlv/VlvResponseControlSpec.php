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
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use PhpSpec\ObjectBehavior;

class VlvResponseControlSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(10, 9, 0);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(VlvResponseControl::class);
    }

    function it_should_get_the_offset()
    {
        $this->getOffset()->shouldBeEqualTo(10);
    }

    function it_should_get_the_count()
    {
        $this->getCount()->shouldBeEqualTo(9);
    }

    function it_should_get_the_context_id()
    {
        $this->getContextId()->shouldBeNull();
    }

    function it_should_get_the_result()
    {
        $this->getResult()->shouldBeEqualTo(0);
    }

    function it_should_be_constructed_from_asn1()
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
