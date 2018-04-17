<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use PhpSpec\ObjectBehavior;

class LdapResultSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(0, 'foo', 'bar');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LdapResult::class);
    }

    function it_should_get_the_diagnostic_message()
    {
        $this->getDiagnosticMessage()->shouldBeEqualTo('bar');
    }

    function it_should_get_the_result_code()
    {
        $this->getResultCode()->shouldBeEqualTo(0);
    }

    function it_should_get_the_dn()
    {
        $this->getDn()->shouldBeLike(new Dn('foo'));
    }

    function it_shouod_get_the_referrals()
    {
        $this->getReferrals()->shouldBeEqualTo([]);
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();
        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType(
                $encoder->encode(Asn1::octetString('ldap://foo'))
                .$encoder->encode(Asn1::octetString('ldap://bar'))
            ))->setIsConstructed(true))
        )]);

        $this->getDn()->shouldBeLike(new Dn('dc=foo,dc=bar'));
        $this->getResultCode()->shouldBeEqualTo(0);
        $this->getDiagnosticMessage()->shouldBeEqualTo('foo');
        $this->getReferrals()->shouldBeLike([
            new LdapUrl('foo'),
            new LdapUrl('bar')
        ]);
    }

    function it_should_throw_a_protocol_exception_if_the_referral_cannot_be_parsed()
    {
        $encoder = new LdapEncoder();
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType(
                $encoder->encode(Asn1::octetString('ldap://foo'))
                .$encoder->encode(Asn1::octetString('bar'))
            ))->setIsConstructed(true))
        )]);
    }
}
