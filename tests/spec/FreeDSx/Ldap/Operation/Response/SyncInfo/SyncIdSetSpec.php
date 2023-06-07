<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Response\SyncInfo;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class SyncIdSetSpec extends ObjectBehavior
{
    function let(): void
    {
        $this->beConstructedWith(
            ['foo', 'bar'],
            false,
            'omnomnom'
        );
    }

    function it_is_initializable(): void
    {
        $this->shouldHaveType(SyncIdSet::class);
    }

    function it_should_get_the_cookie(): void
    {
        $this->getCookie()->shouldBeEqualTo('omnomnom');
    }

    function it_should_get_whether_to_refresh_deletes(): void
    {
        $this->getRefreshDeletes()->shouldBeEqualTo(false);
    }

    function it_should_get_the_entry_uuids(): void
    {
        $this->getEntryUuids()->shouldBeEqualTo(['foo', 'bar']);
    }

    function it_should_have_the_correct_response_name(): void
    {
        $this->getName()->shouldBeEqualTo(IntermediateResponse::OID_SYNC_INFO);
    }

    function it_should_be_constructed_from_ASN1(): void
    {
        $encoder = new LdapEncoder();

        $this::fromAsn1(Asn1::application(25, Asn1::sequence(
            Asn1::context(0, Asn1::octetString(IntermediateResponse::OID_SYNC_INFO)),
            Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::context(3, Asn1::sequence(
                Asn1::octetString('omnomnom'),
                Asn1::boolean(false),
                Asn1::setOf(Asn1::octetString('foo'), Asn1::octetString('bar'))
            )))))
        )))->shouldBeLike(new SyncIdSet(['foo', 'bar'], false, 'omnomnom'));
    }

    function it_should_generate_correct_ASN1(): void
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::application(25, Asn1::sequence(
            Asn1::context(0, Asn1::octetString(IntermediateResponse::OID_SYNC_INFO)),
            Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::context(3, Asn1::sequence(
                Asn1::octetString('omnomnom'),
                Asn1::boolean(false),
                Asn1::setOf(Asn1::octetString('foo'), Asn1::octetString('bar'))
            )))))
        )));
    }
}
