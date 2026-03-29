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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class WriteOperationDispatcherTest extends TestCase
{
    private WriteRequestInterface&MockObject $mockRequest;

    protected function setUp(): void
    {
        $this->mockRequest = $this->createMock(WriteRequestInterface::class);
    }

    private function handler(bool $supports): WriteHandlerInterface&MockObject
    {
        $handler = $this->createMock(WriteHandlerInterface::class);
        $handler->method('supports')->willReturn($supports);

        return $handler;
    }

    public function test_throws_unwilling_to_perform_when_no_handlers_registered(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        (new WriteOperationDispatcher())->dispatch($this->mockRequest);
    }

    public function test_throws_unwilling_to_perform_when_no_handler_supports_request(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        (new WriteOperationDispatcher(
            $this->handler(false),
            $this->handler(false),
        ))->dispatch($this->mockRequest);
    }

    public function test_dispatches_to_first_supporting_handler(): void
    {
        $handler = $this->handler(true);
        $handler->expects(self::once())->method('handle')->with($this->mockRequest);

        (new WriteOperationDispatcher($handler))->dispatch($this->mockRequest);
    }

    public function test_stops_after_first_matching_handler(): void
    {
        $first = $this->handler(true);
        $first->expects(self::once())->method('handle');

        $second = $this->handler(true);
        $second->expects(self::never())->method('handle');

        (new WriteOperationDispatcher($first, $second))->dispatch($this->mockRequest);
    }

    public function test_skips_non_supporting_handlers_before_matching(): void
    {
        $skip = $this->handler(false);
        $skip->expects(self::never())->method('handle');

        $match = $this->handler(true);
        $match->expects(self::once())->method('handle')->with($this->mockRequest);

        (new WriteOperationDispatcher($skip, $match))->dispatch($this->mockRequest);
    }
}
