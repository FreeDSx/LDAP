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

namespace spec\FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use PhpSpec\ObjectBehavior;

class ControlSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('foo');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(Control::class);
    }

    public function it_should_get_the_control_type(): void
    {
        $this->getTypeOid()->shouldBeEqualTo('foo');
        $this->setTypeOid('bar')->getTypeOid()->shouldBeEqualTo('bar');
    }

    public function it_should_get_the_control_value(): void
    {
        $this->getValue()->shouldBeEqualTo(null);
        $this->setValue('bar')->getValue()->shouldBeEqualTo('bar');
    }

    public function it_should_get_the_criticality(): void
    {
        $this->getCriticality()->shouldBeEqualTo(false);
        $this->setCriticality(true)->getCriticality()->shouldBeEqualTo(true);
    }

    public function it_should_have_a_string_representation_of_the_oid_type(): void
    {
        $this->__toString()->shouldBeEqualTo('foo');
    }

    public function it_should_generate_correct_ASN1(): void
    {
        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::boolean(false)
        ));
    }

    public function it_should_be_constructed_from_ASN1(): void
    {
        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foobar'),
            Asn1::boolean(true)
        )]);

        $this->getTypeOid()->shouldBeEqualTo('foobar');
        $this->getCriticality()->shouldBeEqualTo(true);
    }
}
