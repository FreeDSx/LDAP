<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Unit\FreeDSx\Ldap\Exception;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use PHPUnit\Framework\TestCase;

final class OperationExceptionTest extends TestCase
{
    private OperationException $subject;

    protected function setUp(): void
    {
        $this->subject = new OperationException();
    }

    public function test_it_should_have_a_default_code_of_operations_error(): void
    {
        self::assertSame(
            ResultCode::OPERATIONS_ERROR,
            $this->subject->getCode(),
        );
    }

    public function test_it_should_get_the_code_short_string(): void
    {
        self::assertSame(
            'operationsError',
            $this->subject->getCodeShort(),
        );
    }

    public function test_it_should_get_the_code_description(): void
    {
        self::assertSame(
            ResultCode::MEANING_DESCRIPTION[ResultCode::OPERATIONS_ERROR],
            $this->subject->getCodeDescription(),
        );
    }

    public function test_it_should_generate_a_message_if_none_was_provided(): void
    {
        self::assertSame(
            'The result code 1 was thrown (operationsError). Indicates that the operation is not properly sequenced with relation to other operations (of same or different type).',
            $this->subject->getMessage(),
        );
    }
}
