<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control\Sync;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class SyncStateControlSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(0, 'foo', 'omnomnom');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SyncStateControl::class);
    }

    function it_should_get_the_state()
    {
        $this->getState()->shouldBeEqualTo(0);
    }

    function it_should_get_the_entry_uuid()
    {
        $this->getEntryUuid()->shouldBeEqualTo('foo');
    }

    function it_should_get_the_cookie()
    {
        $this->getCookie()->shouldBeEqualTo('omnomnom');
    }

    function it_should_generate_correct_asn1()
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_SYNC_STATE),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::enumerated(0),
                Asn1::octetString('foo'),
                Asn1::octetString('omnomnom')
            )))
        ));
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::octetString(Control::OID_SYNC_STATE),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::enumerated(0),
                Asn1::octetString('foo'),
                Asn1::octetString('omnomnom')
            )))
        )]);

        $this->getState()->shouldBeEqualTo(0);
        $this->getEntryUuid()->shouldBeEqualTo('foo');
        $this->getCookie()->shouldBeEqualTo('omnomnom');
        $this->getTypeOid()->shouldBeEqualTo(Control::OID_SYNC_STATE);
    }
}
