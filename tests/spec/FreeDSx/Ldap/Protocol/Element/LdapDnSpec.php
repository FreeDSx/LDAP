<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\Element;

use FreeDSx\Ldap\Asn1\Type\OctetStringType;
use FreeDSx\Ldap\Protocol\Element\LdapDn;
use FreeDSx\Ldap\Protocol\Element\LdapString;
use PhpSpec\ObjectBehavior;

class LdapDnSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LdapDn::class);
    }

    function it_should_be_an_instance_of_octet_string()
    {
        $this->beAnInstanceOf(OctetStringType::class);
    }

    function it_should_extend_ldap_string()
    {
        $this->beAnInstanceOf(LdapString::class);
    }
}
