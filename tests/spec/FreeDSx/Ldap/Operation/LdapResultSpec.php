<?php

declare(strict_types=1);

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
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class LdapResultSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(0, 'foo', 'bar');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(LdapResult::class);
    }

    public function it_should_get_the_diagnostic_message(): void
    {
        $this->getDiagnosticMessage()->shouldBeEqualTo('bar');
    }

    public function it_should_get_the_result_code(): void
    {
        $this->getResultCode()->shouldBeEqualTo(0);
    }

    public function it_should_get_the_dn(): void
    {
        $this->getDn()->shouldBeLike(new Dn('foo'));
    }

    public function it_shouod_get_the_referrals(): void
    {
        $this->getReferrals()->shouldBeEqualTo([]);
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();
        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType(
                $encoder->encode(Asn1::octetString('ldap://foo'))
                . $encoder->encode(Asn1::octetString('ldap://bar'))
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

    public function it_should_throw_a_protocol_exception_if_the_referral_cannot_be_parsed(): void
    {
        $encoder = new LdapEncoder();
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType(
                $encoder->encode(Asn1::octetString('ldap://foo'))
                . $encoder->encode(Asn1::octetString('bar'))
            ))->setIsConstructed(true))
        )]);
    }
}
