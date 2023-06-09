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

namespace spec\FreeDSx\Ldap\Control\Sync;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class SyncDoneControlSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('omnomnom', false);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SyncDoneControl::class);
    }

    public function it_should_get_refresh_deletes(): void
    {
        $this->getRefreshDeletes()->shouldBeEqualTo(false);
    }

    public function it_should_get_the_cookie(): void
    {
        $this->getCookie()->shouldBeEqualTo('omnomnom');
    }

    public function it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_SYNC_DONE),
            Asn1::boolean(true),
            Asn1::octetString(
                $encoder->encode(Asn1::sequence(
                    Asn1::octetString('omnomnom'),
                    Asn1::boolean(false)
                ))
            )
        ));
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::octetString(Control::OID_SYNC_DONE),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::octetString('omnomnom'),
                Asn1::boolean(false)
            )))
        )]);

        $this->getRefreshDeletes()->shouldBeEqualTo(false);
        $this->getCookie()->shouldBeEqualTo('omnomnom');
        $this->getTypeOid()->shouldBeEqualTo(Control::OID_SYNC_DONE);
    }
}
