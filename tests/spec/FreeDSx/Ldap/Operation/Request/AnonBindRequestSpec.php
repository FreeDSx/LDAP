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
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use PhpSpec\ObjectBehavior;

class AnonBindRequestSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(AnonBindRequest::class);
    }

    function it_should_extend_bind_request()
    {
        $this->shouldBeAnInstanceOf(BindRequest::class);
    }

    function it_should_default_to_ldap_v3()
    {
        $this->getVersion()->shouldBeEqualTo(3);
    }

    function it_should_have_an_empty_username_by_default()
    {
        $this->getUsername()->shouldBeEqualTo('');
    }

    function it_should_set_the_username()
    {
        $this->setUsername('foo');
        $this->getUsername()->shouldBeEqualTo('foo');
    }

    function it_should_generate_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(0, Asn1::sequence(
            Asn1::integer(3),
            Asn1::octetString(''),
            Asn1::context(0, Asn1::octetString(''))
        )));
    }

    function it_should_be_constructed_from_asn1()
    {
        $anon = new AnonBindRequest('foo', 2);

        $this::fromAsn1($anon->toAsn1())->shouldBeLike($anon);
    }

    function it_should_check_that_a_password_is_empty_properly()
    {
        $this::fromAsn1((new SimpleBindRequest('foo', '0'))->toAsn1())->shouldNotBeAnInstanceOf(AnonBindRequest::class);
    }

    function it_should_detect_invalid_asn1()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::integer(2)]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence()]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::integer(2)
        )]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::integer(3),
            Asn1::octetString('foo'),
            Asn1::context(3, Asn1::octetString('foo'))
        )]);
    }
}
