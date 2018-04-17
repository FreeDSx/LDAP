<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Factory\ControlFactory;
use PhpSpec\ObjectBehavior;

class ControlFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ControlFactory::class);
    }

    function it_should_get_a_normal_control_class_for_an_asn1_control_with_no_mapping()
    {
        $this::get((new Control('foo', true, 'bar'))->toAsn1())->shouldBeLike(New Control(
           'foo', true, 'bar'
        ));
    }

    function it_should_get_a_mapped_control_from_asn1()
    {
        $this::get((new PagingControl(100, 'foo'))->toAsn1())->setValue(null)->shouldBeLike(new PagingControl(100, 'foo'));
    }

    function it_should_detect_an_invalid_control()
    {
        $this->shouldThrow(ProtocolException::class)->duringGet(Asn1::octetString('foo'));
        $this->shouldThrow(ProtocolException::class)->duringGet(Asn1::sequence(Asn1::integer(1)));
    }

    function it_should_check_if_a_control_has_a_mapping()
    {
        $this::has(Control::OID_PAGING)->shouldBeEqualTo(true);
        $this::has('foo')->shouldBeEqualTo(false);
    }

    function it_should_set_a_control_oid_mapping()
    {
        $this::set('foo', Control::class);
        $this::has('foo')->shouldBeEqualTo(true);
    }
}
