<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control\Sorting;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use PhpSpec\ObjectBehavior;

class SortingResponseControlSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(0, 'cn');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SortingResponseControl::class);
    }

    function it_should_get_the_result()
    {
        $this->getResult()->shouldBeEqualTo(0);
    }

    function it_should_get_the_attribute()
    {
        $this->getAttribute()->shouldBeEqualTo('cn');
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();

        $this::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_SORTING_RESPONSE),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::enumerated(0),
                Asn1::octetString('cn')
            )))
        ))->setValue(null)->shouldBeLike(new SortingResponseControl(0, 'cn'));
    }

    function it_should_generate_correct_asn1()
    {
        $encoder = new LdapEncoder();
        $this->toAsn1()->shouldBeLike(
            Asn1::sequence(
                Asn1::octetString(Control::OID_SORTING_RESPONSE),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::enumerated(0),
                    Asn1::context(0, Asn1::octetString('cn'))
                )))
            )
        );
    }
}
