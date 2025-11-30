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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use Closure;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestCanceler;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class RequestCancelerTest extends TestCase
{
    private RequestCanceler $subject;

    private ClientQueue&MockObject $mockQueue;

    private Closure $processorForTesting;

    private int $closureCalls = 0;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ClientQueue::class);
        $this->processorForTesting = (function (LdapMessageResponse $response) {
            $this->closureCalls++;
        })(...);

        $this->subject = new RequestCanceler($this->mockQueue);
    }

    public function test_it_should_return_the_cancel_response(): void
    {
        $cancelResponse = new ExtendedResponse(new LdapResult(ResultCode::CANCELED));
        $this->mockQueue
            ->method('getMessage')
            ->will($this->onConsecutiveCalls(
                new LdapMessageResponse(1, new SearchResultEntry(Entry::create(''))),
                new LdapMessageResponse(1, new SearchResultReference()),
                new LdapMessageResponse(2, $cancelResponse),
            ));

        $this->mockQueue
            ->method('generateId')
            ->willReturn(2);

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(self::callback(
                fn (LdapMessageRequest $message) => $message->getRequest() instanceof CancelRequest
            ));

        self::assertSame(
            $cancelResponse,
            $this->subject->cancel(1)
        );
    }

    public function test_it_should_keep_processing_on_the_continue_strategy(): void
    {
        $this->subject = new RequestCanceler(
            $this->mockQueue,
            SearchRequest::CANCEL_CONTINUE,
            $this->processorForTesting,
        );

        $this->mockQueue
            ->method('sendMessage')
            ->willReturnSelf();

        $this->mockQueue
            ->method('getMessage')
            ->will($this->onConsecutiveCalls(
                new LdapMessageResponse(1, new SearchResultEntry(Entry::create(''))),
                new LdapMessageResponse(1, new SearchResultReference()),
                new LdapMessageResponse(2, new ExtendedResponse(new LdapResult(ResultCode::CANCELED))),
            ));

        $this->mockQueue
            ->method('generateId')
            ->willReturn(2);

        $this->subject->cancel(1);

        self::assertSame(
            2,
            $this->closureCalls,
        );
    }

    public function test_it_should_throw_an_operation_error_if_the_cancel_result_code_was_not_success(): void
    {
        $cancelResponse = new ExtendedResponse(new LdapResult(
            ResultCode::TOO_LATE,
            '',
            'Fail'
        ));

        $this->mockQueue
            ->method('getMessage')
            ->willReturn(new LdapMessageResponse(2, $cancelResponse));

        $this->mockQueue
            ->method('generateId')
            ->willReturn(2);

        $this->mockQueue
            ->method('sendMessage')
            ->willReturnSelf();

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::TOO_LATE);

        $this->subject->cancel(1);
    }
}
