<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Exception;

use FreeDSx\Ldap\Exception\PartialPduException;
use PhpSpec\ObjectBehavior;

class PartialPduExceptionSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(PartialPduException::class);
    }

    function it_should_extend_exception()
    {
        $this->shouldBeAnInstanceOf('\Exception');
    }
}
