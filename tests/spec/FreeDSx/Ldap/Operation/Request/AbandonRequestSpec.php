<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use PhpSpec\ObjectBehavior;

class AbandonRequestSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(AbandonRequest::class);
    }

    function it_should_get_the_message_id()
    {
        $this->getMessageId()->shouldBeEqualTo(1);
        $this->setMessageId(2)->getMessageId()->shouldBeEqualTo(2);
    }

    function it_should_generate_correct_ASN1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(16, Asn1::integer(1)));
    }

    function it_should_be_constructed_from_ASN1()
    {
        $this::fromAsn1(Asn1::application(16, Asn1::integer(1)))
            ->shouldBeLike(new AbandonRequest(1));
    }

    function it_should_not_allow_non_integers_from_ASN1()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::application(16, Asn1::octetString(1))]);
    }
}
