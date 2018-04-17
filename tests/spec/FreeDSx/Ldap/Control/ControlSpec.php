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
use FreeDSx\Ldap\Control\Control;
use PhpSpec\ObjectBehavior;

class ControlSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Control::class);
    }

    function it_should_get_the_control_type()
    {
        $this->getTypeOid()->shouldBeEqualTo('foo');
        $this->setTypeOid('bar')->getTypeOid()->shouldBeEqualTo('bar');
    }

    function it_should_get_the_control_value()
    {
        $this->getValue()->shouldBeEqualTo(null);
        $this->setValue('bar')->getValue()->shouldBeEqualTo('bar');
    }

    function it_should_get_the_criticality()
    {
        $this->getCriticality()->shouldBeEqualTo(false);
        $this->setCriticality(true)->getCriticality()->shouldBeEqualTo(true);
    }

    function it_should_have_a_string_representation_of_the_oid_type()
    {
        $this->__toString()->shouldBeEqualTo('foo');
    }

    function it_should_generate_correct_ASN1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::sequence(
           Asn1::octetString('foo'),
           Asn1::boolean(false)
        ));
    }

    function it_should_be_constructed_from_ASN1()
    {
        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foobar'),
            Asn1::boolean(true)
        )]);

        $this->getTypeOid()->shouldBeEqualTo('foobar');
        $this->getCriticality()->shouldBeEqualTo(true);
    }
}
