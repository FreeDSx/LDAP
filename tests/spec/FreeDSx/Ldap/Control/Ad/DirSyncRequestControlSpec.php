<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control\Ad;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Ad\DirSyncRequestControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class DirSyncRequestControlSpec extends ObjectBehavior
{
    public function it_is_initializable()
    {
        $this->shouldHaveType(DirSyncRequestControl::class);
    }

    public function it_should_set_the_flags()
    {
        $this->setFlags(DirSyncRequestControl::FLAG_PUBLIC_DATA_ONLY);
        $this->getFlags()->shouldBeEqualTo(DirSyncRequestControl::FLAG_PUBLIC_DATA_ONLY);
    }

    public function it_should_have_incremental_values_as_the_default_flags()
    {
        $this->getFlags()->shouldBeEqualTo((int) DirSyncRequestControl::FLAG_INCREMENTAL_VALUES);
    }

    public function it_should_set_the_cookie()
    {
        $this->setCookie('foo');
        $this->getCookie()->shouldBeEqualTo('foo');
    }

    public function it_should_have_an_empty_cookie_by_default()
    {
        $this->getCookie()->shouldBeEqualTo('');
    }

    public function it_should_set_the_max_bytes()
    {
        $this->setMaxBytes(2000);
        $this->getMaxBytes()->shouldBeEqualTo(2000);
    }

    public function it_should_have_the_max_value_for_max_bytes_by_default()
    {
        $this->getMaxBytes()->shouldBeEqualTo(2147483647);
    }

    public function it_should_generate_correct_ASN1()
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_DIR_SYNC),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(-0x80000000),
                Asn1::integer(2147483647),
                Asn1::octetString('')
            )))
        ));
    }

    public function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();

        $this::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_DIR_SYNC),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(-0x80000000),
                Asn1::integer(2147483647),
                Asn1::octetString('')
            )))
        ))->setValue(null)->shouldBeLike(new DirSyncRequestControl());
    }
}
