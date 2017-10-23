<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Operation\Request;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Entry\Dn;
use PhpDs\Ldap\Exception\ProtocolException;
use PhpDs\Ldap\Operation\Request\DeleteRequest;
use PhpSpec\ObjectBehavior;

class DeleteRequestSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('cn=foo,dc=foo,dc=bar');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(DeleteRequest::class);
    }

    function it_should_set_the_dn()
    {
        $this->getDn()->shouldBeLike(new Dn('cn=foo,dc=foo,dc=bar'));
        $this->setDn(new Dn('foo'))->getDn()->shouldBeLike(new Dn('foo'));
    }

    function it_should_generate_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(10, Asn1::ldapDn('cn=foo,dc=foo,dc=bar')));
    }

    function it_should_be_constructed_from_asn1()
    {
        $this->beConstructedThrough('fromAsn1', [Asn1::application(10, Asn1::octetString(
            'dc=foo,dc=bar'
        ))]);

        $this->getDn()->shouldBeLike(new Dn('dc=foo,dc=bar'));
    }

    function it_should_not_be_constructed_from_invalid_asn1()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::application(11, Asn1::octetString(
            'dc=foo,dc=bar'
        ))]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::application(11, Asn1::integer(
            2
        ))]);
    }
}
