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
use FreeDSx\Ldap\Control\Ad\DirSyncResponseControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class DirSyncResponseControlSpec extends ObjectBehavior
{
    public function let()
    {
        $this->beConstructedWith(0);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(DirSyncResponseControl::class);
    }

    public function it_should_get_the_more_results_value()
    {
        $this->getMoreResults()->shouldBeEqualTo(0);
    }

    public function it_should_return_false_for_has_more_results_when_more_results_is_0()
    {
        $this->hasMoreResults()->shouldBeEqualTo(false);
    }

    public function it_should_return_false_for_has_more_results_when_more_results_is_not_0()
    {
        $this->beConstructedWith(1);
        $this->hasMoreResults()->shouldBeEqualTo(true);
    }

    public function it_should_get_the_cookie()
    {
        $this->getCookie()->shouldBeEqualTo('');
    }

    public function it_should_get_the_unused_value()
    {
        $this->getUnused(0);
    }

    public function it_should_generate_correct_ASN1()
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_DIR_SYNC),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(0),
                Asn1::integer(0),
                Asn1::octetString('')
            )))
        ));
    }

    public function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();

        $this::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_DIR_SYNC),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(0),
                Asn1::integer(0),
                Asn1::octetString('')
            )))
        ))->setValue(null)->shouldBeLike(new DirSyncResponseControl(0));
    }
}
