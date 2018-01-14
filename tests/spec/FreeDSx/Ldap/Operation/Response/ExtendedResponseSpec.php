<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use PhpSpec\ObjectBehavior;

class ExtendedResponseSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new LdapResult(0, 'dc=foo,dc=bar', 'foo'), 'foo', 'bar');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ExtendedResponse::class);
    }

    function it_should_get_the_name()
    {
        $this->getName()->shouldBeEqualTo('foo');
    }

    function it_should_get_the_value()
    {
        $this->getValue()->shouldBeEqualTo('bar');
    }

    function it_should_be_constructed_from_asn1()
    {
        $this->beConstructedThrough('fromAsn1', [Asn1::application(24,Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::ldapDn('dc=foo,dc=bar'),
            Asn1::ldapString('foo'),
            Asn1::context(3, Asn1::sequence(
                Asn1::ldapString('ldap://foo'),
                Asn1::ldapString('ldap://bar')
            )),
            Asn1::context(10, Asn1::ldapOid('foo')),
            Asn1::context(11, Asn1::octetString('bar'))
        ))]);

        $this->getName()->shouldBeEqualTo('foo');
        $this->getValue()->shouldBeEqualTo('bar');
    }
}
