<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Asn1\Type;

use PhpDs\Ldap\Asn1\Type\AbstractType;
use PhpDs\Ldap\Asn1\Type\EnumeratedType;
use PhpSpec\ObjectBehavior;

class EnumeratedTypeSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(EnumeratedType::class);
    }

    function it_should_get_the_value()
    {
        $this->getValue()->shouldBeEqualTo(1);

        $this->setValue(2)->getValue()->shouldBeEqualTo(2);
    }

    function it_should_have_a_default_tag_type()
    {
        $this->getTagNumber()->shouldBeEqualTo(AbstractType::TAG_TYPE_ENUMERATED);
    }
}
