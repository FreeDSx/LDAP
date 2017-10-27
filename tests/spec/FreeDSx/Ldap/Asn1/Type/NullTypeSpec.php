<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Asn1\Type;

use FreeDSx\Ldap\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Asn1\Type\NullType;
use PhpSpec\ObjectBehavior;

class NullTypeSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(NullType::class);
    }

    function it_should_have_a_null_value()
    {
        $this->getValue()->shouldBeNull();
    }

    function it_should_have_a_default_tag_type()
    {
        $this->getTagNumber()->shouldBeEqualTo(AbstractType::TAG_TYPE_NULL);
    }
}
