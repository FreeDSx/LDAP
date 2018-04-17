<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Exception;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use PhpSpec\ObjectBehavior;

class OperationExceptionSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(OperationException::class);
    }

    function it_should_have_a_default_code_of_operations_error()
    {
        $this->getCode()->shouldBeEqualTo(ResultCode::OPERATIONS_ERROR);
    }
}
