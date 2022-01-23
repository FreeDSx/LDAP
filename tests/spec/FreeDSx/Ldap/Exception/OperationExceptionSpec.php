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
    public function it_is_initializable()
    {
        $this->shouldHaveType(OperationException::class);
    }

    public function it_should_have_a_default_code_of_operations_error()
    {
        $this->getCode()->shouldBeEqualTo(ResultCode::OPERATIONS_ERROR);
    }

    public function it_should_get_the_code_short_string()
    {
        $this->getCodeShort()->shouldBeEqualTo('operationsError');
    }

    public function it_should_get_the_code_description()
    {
        $this->getCodeDescription()->shouldBeEqualTo(ResultCode::MEANING_DESCRIPTION[ResultCode::OPERATIONS_ERROR]);
    }

    public function it_should_generate_a_message_if_none_was_provided()
    {
        $this->getMessage()->shouldBeEqualTo('The result code 1 was thrown (operationsError). Indicates that the operation is not properly sequenced with relation to other operations (of same or different type).');
    }
}
