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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Protocol\Factory\OperationFactory;
use PhpSpec\ObjectBehavior;

class OperationFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(OperationFactory::class);
    }

    function it_should_check_if_an_operation_is_mapped_by_its_application_tag()
    {
        $this::has(1)->shouldBeEqualTo(true);
        $this::has(89)->shouldBeEqualTo(false);
    }

    function it_should_set_an_operation_mapping_by_tag_and_class_name()
    {
        $this::set(40, AddRequest::class);
        $this::has(40)->shouldBeEqualTo(true);
    }

    function it_should_not_map_a_class_that_does_not_implement_the_right_interface()
    {
        $this->shouldThrow(InvalidArgumentException::class)->during('set', [41, Entry::class]);
    }

    function it_should_not_map_a_class_that_does_not_exit()
    {
        $this->shouldThrow(InvalidArgumentException::class)->during('set', [41, 'foo']);
    }

    function it_should_get_an_operation_mapped_by_the_asn1_type()
    {
        $this::get(Asn1::application(10, Asn1::octetString('cn=foo,dc=foo,dc=bar')))->shouldBeLike(new DeleteRequest('cn=foo,dc=foo,dc=bar'));
    }
}
