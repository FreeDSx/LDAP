<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use PhpSpec\ObjectBehavior;

class DeleteResponseSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(0, 'foo', 'bar');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(DeleteResponse::class);
    }

    function it_should_extend_ldap_result()
    {
        $this->shouldBeAnInstanceOf(LdapResult::class);
    }
}
