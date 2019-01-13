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
use FreeDSx\Ldap\Control\Ad\PolicyHintsControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class PolicyHintsControlSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(PolicyHintsControl::class);
    }

    function it_should_be_enabled_by_default()
    {
        $this->getIsEnabled()->shouldBeEqualTo(true);
    }

    function it_should_set_whether_or_not_it_is_enabled()
    {
        $this->setIsEnabled(false)->getIsEnabled()->shouldBeEqualTo(false);
    }

    function it_should_generate_correct_ASN1()
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_POLICY_HINTS),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(1)
            )))
        ));
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();

        $this::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_POLICY_HINTS),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(1)
            )))
        ))->setValue(null)->shouldBeLike(new PolicyHintsControl());
    }
}
