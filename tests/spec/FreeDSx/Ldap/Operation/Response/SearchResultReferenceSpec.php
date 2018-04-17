<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use PhpSpec\ObjectBehavior;

class SearchResultReferenceSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new LdapUrl('foo'), new LdapUrl('bar'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SearchResultReference::class);
    }

    function it_should_get_the_referrals()
    {
        $this->getReferrals()->shouldBeLike([
            new LdapUrl('foo'),
            new LdapUrl('bar')
        ]);
    }

    function it_should_be_constructed_from_asn1()
    {
        $this->beConstructedThrough('fromAsn1', [Asn1::application(19, Asn1::sequence(
            Asn1::octetString('ldap://foo'),
            Asn1::octetString('ldap://bar')
        ))]);

        $this->getReferrals()->shouldBeLike([
            new LdapUrl('foo'),
            new LdapUrl('bar')
        ]);
    }

    function it_should_generate_correct_asn1()
    {
        $this::toAsn1()->shouldBeLike(Asn1::application(19, Asn1::sequence(
            Asn1::octetString('ldap://foo/'),
            Asn1::octetString('ldap://bar/')
        )));
    }

    function it_should_throw_a_protocol_exception_if_the_referral_cannot_be_parsed()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::application(19, Asn1::sequence(
            Asn1::octetString('ldap://foo/'),
            Asn1::octetString('?bar')
        ))]);
    }
}
