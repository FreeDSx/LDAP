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
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use PhpSpec\ObjectBehavior;

class LdapMessageResponseSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1, new SearchResponse(new SearchResultDone(0, 'dc=foo,dc=bar', ''), new Entries()), new Control('foo'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LdapMessageResponse::class);
    }

    function it_should_get_the_response()
    {
        $this->getResponse()->shouldBeAnInstanceOf(SearchResponse::class);
    }

    function it_should_get_the_controls()
    {
        $this->controls()->has('foo')->shouldBeEqualTo(true);
    }

    function it_should_get_the_message_id()
    {
        $this->getMessageId()->shouldBeEqualTo(1);
    }

    function it_should_be_constructed_from_ASN1()
    {
        $encoder = new LdapEncoder();

        $this->beConstructedThrough('fromAsn1',[Asn1::sequence(
            Asn1::integer(3),
            Asn1::application(11, Asn1::sequence(
                Asn1::integer(0),
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::octetString('')
            )),
            Asn1::context(0, (new IncompleteType($encoder->encode((new Control('foo'))->toAsn1())))->setIsConstructed(true))
        )]);

        $this->getMessageId()->shouldBeEqualTo(3);
        $this->getResponse()->shouldBeLike(new DeleteResponse(0, 'dc=foo,dc=bar', ''));
        $this->controls()->has('foo')->shouldBeEqualTo(true);
    }
}
