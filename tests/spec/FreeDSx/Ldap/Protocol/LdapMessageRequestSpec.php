<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Protocol\LdapMessage;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use PhpSpec\ObjectBehavior;

class LdapMessageRequestSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1, new DeleteRequest('dc=foo,dc=bar'), new Control('foo'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LdapMessageRequest::class);
    }

    function it_should_extend_ldap_message()
    {
        $this->shouldBeAnInstanceOf(LdapMessage::class);
    }

    function it_should_get_the_response()
    {
        $this->getRequest()->shouldBeAnInstanceOf(DeleteRequest::class);
    }

    function it_should_get_the_controls()
    {
        $this->controls()->has('foo')->shouldBeEqualTo(true);
    }

    function it_should_get_the_message_id()
    {
        $this->getMessageId()->shouldBeEqualTo(1);
    }

    function it_should_generate_correct_ASN1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::integer(1),
            Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
            Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1()))
        ));
    }
}
