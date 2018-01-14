<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Asn1\Encoder\BerEncoder;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Protocol\Factory\ExtendedResponseFactory;
use PhpSpec\ObjectBehavior;

class ExtendedResponseFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ExtendedResponseFactory::class);
    }

    function it_should_check_if_a_mapping_exists_for_a_specific_request_oid()
    {
        $this::has(ExtendedRequest::OID_PWD_MODIFY)->shouldBeEqualTo(true);
        $this::has('foo')->shouldBeEqualTo(false);
    }

    function it_should_add_a_mapping_for_a_specific_oid()
    {
        $this::set('foo', PasswordModifyResponse::class);
        $this::has('foo')->shouldBeEqualTo(true);
    }

    function it_should_get_a_mapping_based_on_an_oid_and_asn1()
    {
        $encoder = new BerEncoder();

        $this->get(Asn1::application(24, Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::ldapDn('dc=foo,dc=bar'),
            Asn1::ldapString('foo'),
            Asn1::context(3, Asn1::sequence(
                Asn1::ldapString('ldap://foo'),
                Asn1::ldapString('ldap://bar')
            )),
            Asn1::context(11, Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::context(0, Asn1::octetString('bleep-blorp'))
            ))))
        )), ExtendedRequest::OID_PWD_MODIFY)->shouldBeLike(new PasswordModifyResponse(
            new LdapResult(0, 'dc=foo,dc=bar', 'foo', new LdapUrl('foo'), new LdapUrl('bar')),
            'bleep-blorp'
        ));
    }
}
