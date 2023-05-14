<?php

namespace spec\FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\SubentriesControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class SubentriesControlSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(SubentriesControl::class);
    }

    function it_should_have_a_default_visibility_of_true()
    {
        $this->getIsVisible()->shouldBeEqualTo(true);
    }

    function it_should_set_the_visibility()
    {
        $this->setIsVisible(false)->getIsVisible()->shouldBeEqualTo(false);
    }

    function it_should_have_the_subentries_oid()
    {
        $this->getTypeOid()->shouldBeEqualTo(Control::OID_SUBENTRIES);
    }

    function it_should_generate_correct_asn1()
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_SUBENTRIES),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::boolean(true)))
        ));
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::octetString(Control::OID_SUBENTRIES),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::boolean(true)))
        )]);

        $this->getIsVisible()->shouldBeEqualTo(true);
        $this->getTypeOid()->shouldBeEqualTo(Control::OID_SUBENTRIES);
    }
}
