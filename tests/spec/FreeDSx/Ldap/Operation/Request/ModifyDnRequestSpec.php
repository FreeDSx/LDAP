<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Rdn;
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
            Asn1::ldapDn('cn=foo,dc=foo,dc=bar'),
            Asn1::ldapString('cn=bar'),
            Asn1::boolean(true)
        )));

        $this->setNewParentDn('dc=foobar');

        $this->toAsn1()->shouldBeLike(Asn1::application(12, Asn1::sequence(
            Asn1::ldapDn('cn=foo,dc=foo,dc=bar'),
            Asn1::ldapString('cn=bar'),
            Asn1::boolean(true),
            Asn1::context(0, Asn1::ldapDn('dc=foobar'))
        )));
    }
}
