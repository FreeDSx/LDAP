<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use PhpSpec\ObjectBehavior;

class PagingControlSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(PagingControl::class);
    }
    function let()
    {
        $this->beConstructedWith(0, 'foo');
    }

    function it_should_default_to_an_empty_cookie_on_construction()
    {
        $this->beConstructedWith(10);

        $this->getCookie()->shouldBeEqualTo('');
    }

    function it_should_set_the_size()
    {
        $this->getSize(0);
        $this->setSize(1)->getSize()->shouldBeEqualTo(1);
    }

    function it_should_set_the_cookie()
    {
        $this->getCookie()->shouldBeEqualTo('foo');
        $this->setCookie('bar')->getCookie()->shouldBeEqualTo('bar');
    }

    function it_should_generate_correct_asn1()
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_PAGING),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(0),
                Asn1::octetString('foo')
            )))
        ));
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::octetString(Control::OID_PAGING),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(1),
                Asn1::octetString('foobar')
            )))
        )]);

        $this->getSize()->shouldBeEqualTo(1);
        $this->getCookie()->shouldBeEqualTo('foobar');
    }
}
