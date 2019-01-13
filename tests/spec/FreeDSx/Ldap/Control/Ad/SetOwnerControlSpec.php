<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control\Ad;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Ad\SetOwnerControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class SetOwnerControlSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SetOwnerControl::class);
    }

    function it_should_get_the_sid()
    {
        $this->getSid()->shouldBeEqualTo('foo');
    }

    function it_should_set_the_sid()
    {
        $this->setSid('bar')->getSid()->shouldBeEqualTo('bar');
    }

    function it_should_generate_correct_ASN1()
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_SET_OWNER),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::octetString('foo')))
        ));
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();

        $this::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_SET_OWNER),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::octetString('foo')))
        ))->setValue(null)->shouldBeLike(new SetOwnerControl('foo'));
    }
}
