<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use PhpSpec\ObjectBehavior;

class AnonBindRequestSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(AnonBindRequest::class);
    }

    function it_should_extend_bind_request()
    {
        $this->shouldBeAnInstanceOf(BindRequest::class);
    }

    function it_should_default_to_ldap_v3()
    {
        $this->getVersion()->shouldBeEqualTo(3);
    }

    function it_should_have_an_empty_username_by_default()
    {
        $this->getUsername()->shouldBeEqualTo('');
    }

    function it_should_set_the_username()
    {
        $this->setUsername('foo');
        $this->getUsername()->shouldBeEqualTo('foo');
    }

    function it_should_generate_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(0, Asn1::sequence(
            Asn1::integer(3),
            Asn1::ldapDn(''),
            Asn1::context(0, Asn1::octetString(''))
        )));
    }
}
