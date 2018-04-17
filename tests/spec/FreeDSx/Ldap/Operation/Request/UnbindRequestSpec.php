<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\NullType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use PhpSpec\ObjectBehavior;

class UnbindRequestSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(UnbindRequest::class);
    }

    function it_should_form_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike((new NullType())->setTagClass(NullType::TAG_CLASS_APPLICATION)->setTagNumber(2));
    }

    function it_should_be_constructed_from_asn1()
    {
        $this::fromAsn1(Asn1::null())->shouldBeLike(new UnbindRequest());
    }

    function it_should_not_be_constructed_from_invalid_asn1()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::octetString('foo')]);
    }
}
