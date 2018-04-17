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
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use PhpSpec\ObjectBehavior;

class BindResponseSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new LdapResult(0, 'foo', 'bar', new LdapUrl('foo')), 'foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(BindResponse::class);
    }

    function it_should_get_the_sasl_creds()
    {
        $this->getSaslCredentials()->shouldBeEqualTo('foo');
    }

    function it_should_get_the_ldap_result_data()
    {
        $this->getResultCode()->shouldBeEqualTo(0);
        $this->getDn()->shouldBeLike(new Dn('foo'));
        $this->getDiagnosticMessage()->shouldBeLike('bar');
        $this->getReferrals()->shouldBeLike([new LdapUrl('foo')]);
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();
        $this->beConstructedThrough('fromAsn1', [Asn1::application(1, Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType($encoder->encode(
                Asn1::octetString('ldap://foo')))
            )->setIsConstructed(true)),
            Asn1::context(7, Asn1::octetString('foo'))
        ))]);

        $this->getSaslCredentials()->shouldBeEqualTo('foo');
        $this->getResultCode()->shouldBeEqualTo(0);
        $this->getDn()->shouldBeLike(new Dn('dc=foo,dc=bar'));
        $this->getDiagnosticMessage()->shouldBeEqualTo('foo');
        $this->getReferrals()->shouldBeLike([new LdapUrl('foo')]);
    }
}
