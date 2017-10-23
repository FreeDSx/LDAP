<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Operation;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Entry\Dn;
use PhpDs\Ldap\Operation\LdapResult;
use PhpDs\Ldap\Operation\Referral;
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
        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::ldapDn('dc=foo,dc=bar'),
            Asn1::ldapString('foo'),
            Asn1::context(3, Asn1::sequence(
                Asn1::ldapString('foo'),
                Asn1::ldapString('bar')
            ))
        )]);

        $this->getDn()->shouldBeLike(new Dn('dc=foo,dc=bar'));
        $this->getResultCode()->shouldBeEqualTo(0);
        $this->getDiagnosticMessage()->shouldBeEqualTo('foo');
        $this->getReferrals()->shouldBeLike([
            new Referral('foo'),
            new Referral('bar')
        ]);
    }
}
