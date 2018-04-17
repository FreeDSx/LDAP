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

use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Ad\SdFlagsControl;
use FreeDSx\Ldap\Control\Control;
use PhpSpec\ObjectBehavior;

class SdFlagsControlSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(SdFlagsControl::DACL_SECURITY_INFORMATION);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SdFlagsControl::class);
    }

    function it_should_get_the_flags()
    {
        $this->getFlags()->shouldBeEqualTo(SdFlagsControl::DACL_SECURITY_INFORMATION);
    }

    function it_should_set_the_flags()
    {
        $this->setFlags(SdFlagsControl::SACL_SECURITY_INFORMATION)->getFlags()->shouldBeEqualTo(SdFlagsControl::SACL_SECURITY_INFORMATION);
    }

    function it_should_generate_correct_ASN1()
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_SD_FLAGS),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(4)
            )))
        ));
    }
}
