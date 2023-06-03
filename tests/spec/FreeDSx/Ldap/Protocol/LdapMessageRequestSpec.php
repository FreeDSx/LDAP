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
    public function let(): void
    {
        $this->beConstructedWith(1, new DeleteRequest('dc=foo,dc=bar'), new Control('foo'));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(LdapMessageRequest::class);
    }

    public function it_should_extend_ldap_message(): void
    {
        $this->shouldBeAnInstanceOf(LdapMessage::class);
    }

    public function it_should_get_the_response(): void
    {
        $this->getRequest()->shouldBeAnInstanceOf(DeleteRequest::class);
    }

    public function it_should_get_the_controls(): void
    {
        $this->controls()->has('foo')->shouldBeEqualTo(true);
    }

    public function it_should_get_the_message_id(): void
    {
        $this->getMessageId()->shouldBeEqualTo(1);
    }

    public function it_should_generate_correct_ASN1(): void
    {
        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::integer(1),
            Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
            Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1()))
        ));
    }
}
