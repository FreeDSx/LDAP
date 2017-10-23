<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Operation\Response;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Entry\Dn;
use PhpDs\Ldap\Operation\LdapResult;
use PhpDs\Ldap\Operation\Response\BindResponse;
use PhpDs\Ldap\Operation\Referral;
use PhpSpec\ObjectBehavior;

class BindResponseSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new LdapResult(0, 'foo', 'bar', new Referral('foo')), 'foo');
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
        $this->getReferrals()->shouldBeLike([new Referral('foo')]);
    }

    function it_should_be_constructed_from_asn1()
    {
        $this->beConstructedThrough('fromAsn1', [Asn1::application(1, Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::ldapDn('dc=foo,dc=bar'),
            Asn1::ldapString('foo'),
            Asn1::context(3, Asn1::sequence(
                Asn1::ldapString('foo')
            )),
            Asn1::context(7, Asn1::octetString('foo'))
        ))]);

        $this->getSaslCredentials()->shouldBeEqualTo('foo');
        $this->getResultCode()->shouldBeEqualTo(0);
        $this->getDn()->shouldBeLike(new Dn('dc=foo,dc=bar'));
        $this->getDiagnosticMessage()->shouldBeEqualTo('foo');
        $this->getReferrals()->shouldBeLike([new Referral('foo')]);
    }
}
