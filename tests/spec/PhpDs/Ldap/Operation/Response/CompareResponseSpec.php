<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Operation\Response;

use PhpDs\Ldap\Operation\LdapResult;
use PhpDs\Ldap\Operation\Response\CompareResponse;
use PhpSpec\ObjectBehavior;

class CompareResponseSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(0, 'foo', 'bar');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(CompareResponse::class);
    }

    function it_should_extend_ldap_result()
    {
        $this->shouldBeAnInstanceOf(LdapResult::class);
    }
}
