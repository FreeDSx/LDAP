<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Asn1\Encoder\BerEncoder;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use PhpSpec\ObjectBehavior;

class CancelRequestSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(CancelRequest::class);
    }

    function it_should_set_the_message_id()
    {
        $this->getMessageId()->shouldBeEqualTo(1);
        $this->setMessageId(2)->getMessageId()->shouldBeEqualTo(2);
    }

    function it_should_generate_correct_asn1()
    {
        $encoder = new BerEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::application(23, Asn1::sequence(
            Asn1::context(0, Asn1::ldapOid(ExtendedRequest::OID_CANCEL)),
            Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(1)
            ))))
        )));
    }
}
