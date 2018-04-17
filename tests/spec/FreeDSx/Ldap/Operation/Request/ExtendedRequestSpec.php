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
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use PhpSpec\ObjectBehavior;

class ExtendedRequestSpec extends ObjectBehavior
{
    public function let()
    {
        $this->beConstructedWith(ExtendedRequest::OID_START_TLS);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ExtendedRequest::class);
    }

    function it_should_get_the_extended_request_name()
    {
        $this->getName()->shouldBeEqualTo('1.3.6.1.4.1.1466.20037');
        $this->setName('foo')->getName()->shouldBeEqualTo('foo');
    }

    function it_should_get_the_extended_request_value()
    {
        $this->setValue('foo')->getValue()->shouldBeEqualTo('foo');
    }

    function it_should_generate_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(23, Asn1::sequence(
            Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_START_TLS))
        )));

        $this->setValue('foo');

        $this->toAsn1()->shouldBeLike(Asn1::application(23, Asn1::sequence(
            Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_START_TLS)),
            Asn1::context(1, Asn1::octetString('foo'))
        )));
    }

    function it_should_be_constructed_from_asn1_with_no_value()
    {
        $request = new ExtendedRequest('foo');

        $this::fromAsn1($request->toAsn1())->shouldBeLike($request);
    }

    function it_should_be_constructed_from_asn1_with_a_value()
    {
        $request = new ExtendedRequest('foo', 'bar');

        $this::fromAsn1($request->toAsn1())->shouldBeLike($request);
    }

    function it_should_detect_invalid_asn1()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::octetString('foo')]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence()]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(Asn1::octetString('foo'))]);
    }
}
