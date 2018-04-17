<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\DnRequestInterface;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use PhpSpec\ObjectBehavior;

class ModifyDnRequestSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('cn=foo,dc=foo,dc=bar', 'cn=bar', true);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ModifyDnRequest::class);
    }

    function it_should_implement_the_DnRequestInterface()
    {
        $this->shouldImplement(DnRequestInterface::class);
    }

    function it_should_set_the_dn()
    {
        $this->getDn()->shouldBeLike(new Dn('cn=foo,dc=foo,dc=bar'));
        $this->setDn(new Dn('foo'))->getDn()->shouldBeLike(new Dn('foo'));
    }

    function it_should_set_the_new_rdn()
    {
        $this->getNewRdn()->shouldBeLike(Rdn::create('cn=bar'));
        $this->setNewRdn(Rdn::create('cn=foo'))->getNewRdn()->shouldBeLike(Rdn::create('cn=foo'));
    }

    function it_should_set_whether_to_delete_the_old_rdn()
    {
        $this->getDeleteOldRdn()->shouldBeEqualTo(true);
        $this->setDeleteOldRdn(false)->getDeleteOldRdn()->shouldBeEqualTo(false);
    }

    function it_should_set_the_new_parent_dn()
    {
        $this->getNewParentDn()->shouldBeNull();
        $this->setNewParentDn(new Dn('foo'))->getNewParentDn()->shouldBeLike(new Dn('foo'));
    }

    function it_should_generate_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(12, Asn1::sequence(
            Asn1::octetString('cn=foo,dc=foo,dc=bar'),
            Asn1::octetString('cn=bar'),
            Asn1::boolean(true)
        )));

        $this->setNewParentDn('dc=foobar');

        $this->toAsn1()->shouldBeLike(Asn1::application(12, Asn1::sequence(
            Asn1::octetString('cn=foo,dc=foo,dc=bar'),
            Asn1::octetString('cn=bar'),
            Asn1::boolean(true),
            Asn1::context(0, Asn1::octetString('dc=foobar'))
        )));
    }

    function it_should_be_constructed_from_asn1()
    {
        $req = new ModifyDnRequest('foo', 'cn=bar', false, 'foobar');
        $this::fromAsn1($req->toAsn1())->shouldBeLike($req);

        $req = new ModifyDnRequest('foo', 'cn=bar', false);
        $this::fromAsn1($req->toAsn1())->shouldBeLike($req);
    }

    function it_should_not_be_constructed_from_invalid_asn1()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::octetString('foo')]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence()]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(Asn1::integer(1))]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::octetString('cn=foo'),
            Asn1::boolean(true),
            Asn1::octetString('foobar')
        )]);
    }
}
