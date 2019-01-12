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
use FreeDSx\Ldap\Control\Ad\ExpectedEntryCountControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class ExpectedEntryCountControlSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1, 50);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ExpectedEntryCountControl::class);
    }

    function it_should_set_the_maximum()
    {
        $this->setMaximum(100)->getMaximum()->shouldBeEqualTo(100);
    }

    function it_should_get_the_maximum()
    {
        $this->getMaximum()->shouldBeEqualTo(50);
    }

    function it_should_set_the_minimum()
    {
        $this->setMinimum(100)->getMinimum()->shouldBeEqualTo(100);
    }

    function it_should_get_the_minimum()
    {
        $this->getMinimum()->shouldBeEqualTo(1);
    }

    function it_should_generate_correct_ASN1()
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_EXPECTED_ENTRY_COUNT),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(1),
                Asn1::integer(50)
            )))
        ));
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();

        $this::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_EXPECTED_ENTRY_COUNT),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(1),
                Asn1::integer(50)
            )))
        ))->setValue(null)->shouldBeLike(new ExpectedEntryCountControl(1, 50));
    }
}
