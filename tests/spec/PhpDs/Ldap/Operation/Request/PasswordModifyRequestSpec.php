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
use PhpDs\Ldap\Asn1\Encoder\BerEncoder;
use PhpDs\Ldap\Operation\Request\ExtendedRequest;
use PhpDs\Ldap\Operation\Request\PasswordModifyRequest;
use PhpSpec\ObjectBehavior;

class PasswordModifyRequestSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo', 'bar', '12345');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(PasswordModifyRequest::class);
    }

    function it_should_get_the_new_password()
    {
        $this->getNewPassword()->shouldBeEqualTo('12345');
        $this->setNewPassword('foo')->getNewPassword()->shouldBeEqualTo('foo');
    }

    function it_should_get_the_old_password()
    {
        $this->getOldPassword()->shouldBeEqualTo('bar');
        $this->setOldPassword('foo')->getOldPassword()->shouldBeEqualTo('foo');
    }

    function it_should_get_the_username()
    {
        $this->getUsername()->shouldBeEqualTo('foo');
        $this->setUsername('bar')->getUsername()->shouldBeEqualTo('bar');
    }

    function it_should_generate_correct_asn1()
    {
        $encoder = new BerEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::application(23, Asn1::sequence(
            Asn1::context(0, Asn1::ldapOid(ExtendedRequest::OID_PWD_MODIFY)),
            Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::context(0, Asn1::octetString('foo')),
                Asn1::context(1, Asn1::octetString('bar')),
                Asn1::context(2, Asn1::octetString('12345'))
            ))))
        )));

        $this->setUsername(null);
        $this->toAsn1()->shouldBeLike(Asn1::application(23, Asn1::sequence(
            Asn1::context(0, Asn1::ldapOid(ExtendedRequest::OID_PWD_MODIFY)),
            Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::context(1, Asn1::octetString('bar')),
                Asn1::context(2, Asn1::octetString('12345'))
            ))))
        )));

        $this->setOldPassword(null);
        $this->toAsn1()->shouldBeLike(Asn1::application(23, Asn1::sequence(
            Asn1::context(0, Asn1::ldapOid(ExtendedRequest::OID_PWD_MODIFY)),
            Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::context(2, Asn1::octetString('12345'))
            ))))
        )));

        $this->setNewPassword(null);
        $this->toAsn1()->shouldBeLike(Asn1::application(23, Asn1::sequence(
            Asn1::context(0, Asn1::ldapOid(ExtendedRequest::OID_PWD_MODIFY)),
            Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence())))
        )));
    }
}
