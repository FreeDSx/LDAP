<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Operation\Request;

use PhpDs\Ldap\Asn1\Type\NullType;
use PhpDs\Ldap\Operation\Request\UnbindRequest;
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
}
