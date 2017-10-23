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

use PhpDs\Ldap\Asn1\Type\IncompleteType;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class IncompleteTypeSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(IncompleteType::class);
    }

    function it_should_have_no_tag_number_by_default()
    {
        $this->getTagNumber()->shouldBeEqualTo(null);
    }
}
