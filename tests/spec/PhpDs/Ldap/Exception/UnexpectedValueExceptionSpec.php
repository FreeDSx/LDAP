<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Exception;

use PhpDs\Ldap\Exception\UnexpectedValueException;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class UnexpectedValueExceptionSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(UnexpectedValueException::class);
    }

    function it_should_extend_exception()
    {
        $this->shouldBeAnInstanceOf('\Exception');
    }
}
