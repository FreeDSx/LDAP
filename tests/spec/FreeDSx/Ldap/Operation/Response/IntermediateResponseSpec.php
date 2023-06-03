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

namespace spec\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use PhpSpec\ObjectBehavior;

class IntermediateResponseSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('foo', 'bar');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(IntermediateResponse::class);
    }

    public function it_should_get_the_name(): void
    {
        $this->getName()->shouldBeEqualTo('foo');
    }

    public function it_should_get_the_value(): void
    {
        $this->getValue()->shouldBeEqualTo('bar');
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $this->beConstructedThrough('fromAsn1', [Asn1::application(25, Asn1::sequence(
            Asn1::context(0, Asn1::octetString('foo')),
            Asn1::context(1, Asn1::octetString('bar'))
        ))]);

        $this->getName()->shouldBeEqualTo('foo');
        $this->getValue()->shouldBeEqualTo('bar');
    }

    public function it_should_generate_correct_asn1(): void
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(25, Asn1::sequence(
            Asn1::context(0, Asn1::octetString('foo')),
            Asn1::context(1, Asn1::octetString('bar'))
        )));
    }
}
