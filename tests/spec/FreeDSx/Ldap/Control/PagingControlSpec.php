<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control;

use FreeDSx\Ldap\Asn1\Encoder\BerEncoder;
use FreeDSx\Ldap\Asn1\Type\BooleanType;
use FreeDSx\Ldap\Asn1\Type\IntegerType;
use FreeDSx\Ldap\Asn1\Type\OctetStringType;
use FreeDSx\Ldap\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Protocol\Element\LdapOid;
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
        $encoder = new BerEncoder();

        $this->toAsn1()->shouldBeLike(new SequenceType(
            new LdapOid(Control::OID_PAGING),
            new BooleanType(false),
            new OctetStringType($encoder->encode(new SequenceType(
                new IntegerType(0),
                new OctetStringType('foo')
            )))
        ));
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new BerEncoder();

        $this->beConstructedThrough('fromAsn1', [new SequenceType(
            new LdapOid(Control::OID_PAGING),
            new BooleanType(false),
            new OctetStringType($encoder->encode(new SequenceType(
                new IntegerType(1),
                new OctetStringType('foobar')
            )))
        )]);

        $this->getSize()->shouldBeEqualTo(1);
        $this->getCookie()->shouldBeEqualTo('foobar');
    }
}
