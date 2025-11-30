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

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientBasicHandler;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ClientBasicHandlerTest extends TestCase
{
    private ClientBasicHandler $subject;

    private ClientQueue&MockObject $mockQueue;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ClientQueue::class);

        $this->subject = new ClientBasicHandler($this->mockQueue);
    }

    public function test_it_should_handle_a_request_and_return_a_response(): void
    {
        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage');

        $this->mockQueue
            ->expects($this->once())
            ->method('getMessage')
            ->with(1)
            ->willReturn(new LdapMessageResponse(
                1,
                new DeleteResponse(0)
            ));

        self::assertNotNull($this->subject->handleRequest(new LdapMessageRequest(
            1,
            new DeleteRequest('cn=foo')
        )));
    }

    public function test_it_should_handle_a_response(): void
    {
        $messageRequest = new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar'));
        $messageFrom = new LdapMessageResponse(1, new BindResponse(new LdapResult(0)));

        self::assertSame(
            $messageFrom,
            $this->subject->handleResponse(
                $messageRequest,
                $messageFrom,
            )
        );
    }

    public function test_it_should_handle_a_response_with_non_error_codes(): void
    {
        $messageRequest = new LdapMessageRequest(1, new CompareRequest('foo', new EqualityFilter('foo', 'bar')));
        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_FALSE));

        self::assertSame(
            $messageFrom,
            $this->subject->handleResponse(
                $messageRequest,
                $messageFrom,
            )
        );

        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_TRUE));

        self::assertSame(
            $messageFrom,
            $this->subject->handleResponse(
                $messageRequest,
                $messageFrom,
            )
        );

        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::REFERRAL));

        self::assertSame(
            $messageFrom,
            $this->subject->handleResponse(
                $messageRequest,
                $messageFrom,
            )
        );
    }

    public function test_it_should_throw_an_operation_exception_on_errors(): void
    {
        $messageRequest = new LdapMessageRequest(1, new CompareRequest('foo', new EqualityFilter('foo', 'bar')));
        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::BUSY));

        $this->expectException(OperationException::class);

        $this->subject->handleResponse(
            $messageRequest,
            $messageFrom,
        );
    }

    public function test_it_should_throw_a_specific_bind_exception_for_a_bind_response(): void
    {
        $messageRequest = new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar'));
        $messageFrom = new LdapMessageResponse(1, new BindResponse(new LdapResult(ResultCode::INVALID_CREDENTIALS, 'foo', 'message')));

        self::expectException(BindException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject->handleResponse(
            $messageRequest,
            $messageFrom,
        );
    }
}
