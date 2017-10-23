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
use PhpDs\Ldap\Asn1\Encoder\BerEncoder;
use PhpDs\Ldap\Entry\Dn;
use PhpDs\Ldap\Operation\LdapResult;
use PhpDs\Ldap\Operation\Response\PasswordModifyResponse;
use PhpSpec\ObjectBehavior;

class PasswordModifyResponseSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new LdapResult(0, 'foo'), '12345');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(PasswordModifyResponse::class);
    }

    function it_should_get_the_result_code()
    {
        $this->getResultCode()->shouldBeEqualTo(0);
    }

    function it_should_get_the_dn()
    {
        $this->getDn()->shouldBeLike(new Dn('foo'));
    }

    function it_should_get_the_generated_password()
    {
        $this->getGeneratedPassword()->shouldBeEqualTo('12345');
    }

    function it_should_be_constructed_from_asn1_with_a_generated_password()
    {
        $encoder = new BerEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::application(24, Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::ldapDn('dc=foo,dc=bar'),
            Asn1::ldapString('foo'),
            Asn1::context(3, Asn1::sequence(
                Asn1::ldapString('foo'),
                Asn1::ldapString('bar')
            )),
            Asn1::context(11, Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::context(0, Asn1::octetString('bleep-blorp'))
            ))))
        ))]);

        $this->getGeneratedPassword()->shouldBeEqualTo('bleep-blorp');
        $this->getResultCode()->shouldBeEqualTo(0);
        $this->getDn()->shouldBeLike(new Dn('dc=foo,dc=bar'));
    }

    function it_should_be_constructed_from_asn1_without_a_generated_password()
    {
        $encoder = new BerEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::application(24, Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::ldapDn('dc=foo,dc=bar'),
            Asn1::ldapString('foo'),
            Asn1::context(3, Asn1::sequence(
                Asn1::ldapString('foo'),
                Asn1::ldapString('bar')
            )),
            Asn1::context(11, Asn1::octetString($encoder->encode(Asn1::sequence())))
        ))]);

        $this->getGeneratedPassword()->shouldBeNull();
    }
}
