<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control;

use FreeDSx\Ldap\Asn1\Encoder\BerEncoder;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use PhpSpec\ObjectBehavior;
use FreeDSx\Ldap\Asn1\Asn1;

class PwdPolicyResponseControlSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1, 2, 3);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(PwdPolicyResponseControl::class);
    }

    function it_should_get_the_error()
    {
        $this->getError()->shouldBeEqualTo(3);
    }

    function it_should_get_the_time_before_expiration()
    {
        $this->getTimeBeforeExpiration()->shouldBeEqualTo(1);
    }

    function it_should_get_the_grace_attempts_remaining()
    {
        $this->getGraceAttemptsRemaining()->shouldBeEqualTo(2);
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new BerEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::ldapOid(Control::OID_PWD_POLICY),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::context(0, Asn1::sequence(Asn1::context(0, Asn1::integer(100)))),
                Asn1::context(1, Asn1::enumerated(2))
            )))
        )]);

        $this->getTimeBeforeExpiration()->shouldBeEqualTo(100);
        $this->getError()->shouldBeEqualTo(2);
        $this->getTypeOid()->shouldBeEqualTo(Control::OID_PWD_POLICY);
        $this->getCriticality()->shouldBeEqualTo(false);
    }

    function it_should_generate_correct_asn1()
    {
        $this->beConstructedWith(100, null, 2);

        $encoder = new BerEncoder();
        $this->toAsn1()->shouldBeLike(
            Asn1::sequence(
                Asn1::ldapOid(Control::OID_PWD_POLICY),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::context(0, Asn1::sequence(Asn1::context(0, Asn1::integer(100)))),
                    Asn1::context(1, Asn1::enumerated(2))
                )))
            )
        );
    }
}
