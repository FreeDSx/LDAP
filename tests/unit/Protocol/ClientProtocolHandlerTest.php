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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ResponseHandlerInterface;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Unit\FreeDSx\Ldap\TestFactoryTrait;

final class ClientProtocolHandlerTest extends TestCase
{
    use TestFactoryTrait;

    private ClientProtocolHandler $subject;

    private ClientQueue&MockObject $mockQueue;

    private ClientQueueInstantiator&MockObject $mockQueueInstantiator;

    private ClientProtocolHandlerFactory&MockObject $mockProtocolHandlerFactory;

    private ResponseHandlerInterface&MockObject $mockResponseHandler;

    private RequestHandlerInterface&MockObject $mockRequestHandler;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ClientQueue::class);
        $this->mockQueueInstantiator = $this->createMock(ClientQueueInstantiator::class);
        $this->mockProtocolHandlerFactory = $this->createMock(ClientProtocolHandlerFactory::class);
        $this->mockResponseHandler = $this->createMock(ResponseHandlerInterface::class);
        $this->mockRequestHandler = $this->createMock(RequestHandlerInterface::class);

        $this->mockProtocolHandlerFactory
            ->expects($this->any())
            ->method('forResponse')
            ->willReturn($this->mockResponseHandler);

        $this->mockProtocolHandlerFactory
            ->expects($this->any())
            ->method('forRequest')
            ->willReturn($this->mockRequestHandler);

        $this->mockQueueInstantiator
            ->expects($this->any())
            ->method('make')
            ->willReturn($this->mockQueue);

        $this->mockQueue
            ->expects($this->any())
            ->method('generateId')
            ->willReturn(1);

        $this->subject = new ClientProtocolHandler(
            new ClientOptions(),
            $this->mockQueueInstantiator,
            $this->mockProtocolHandlerFactory,
        );
    }

    public function test_it_should_close_the_queue_on_a_disconnect_notice_and_throw_a_connection_exception(): void
    {
        $this->expectException(ConnectionException::class);

        $this->mockRequestHandler
            ->expects($this->any())
            ->method('handleRequest')
            ->willThrowException(
                new UnsolicitedNotificationException(
                    'foo',
                    0,
                    null,
                    ExtendedResponse::OID_NOTICE_OF_DISCONNECTION
                )
            );

        $this->mockQueue
            ->expects($this->once())
            ->method('close');

        $this->subject->send(new DeleteRequest('foo'));
    }

    public function test_it_should_throw_a_ldap_specific_connection_exception_on_socket_issues(): void
    {
        $this->expectException(ConnectionException::class);

        $this->mockRequestHandler
            ->expects($this->any())
            ->method('handleRequest')
            ->willThrowException(new \FreeDSx\Socket\Exception\ConnectionException(
                'foo'
            ));

        $this->subject->send(new DeleteRequest('foo'));
    }

    public function test_it_should_send_a_request_and_handle_a_response(): void
    {
        $request = new DeleteRequest('cn=foo');
        $messageResponse = new LdapMessageResponse(1, new DeleteResponse(0));
        $messageRequest = new LdapMessageRequest(1, $request);

        $this->mockRequestHandler
            ->expects($this->once())
            ->method('handleRequest')
            ->with($this->callback(
                fn (LdapMessageRequest $messageRequest) => $messageRequest->getRequest() === $request)
            )->willReturn($messageResponse);

        $this->mockResponseHandler
            ->expects($this->once())
            ->method('handleResponse')
            ->with($messageRequest, $messageResponse)
            ->willReturn($messageResponse);

        self::assertSame(
            $messageResponse,
            $this->subject->send($request)
        );
    }

    public function test_it_should_return_null_if_no_response_was_returned(): void
    {
        $request = new UnbindRequest();

        $this->mockRequestHandler
            ->expects($this->once())
            ->method('handleRequest')
            ->with($this->callback(
                fn (LdapMessageRequest $messageRequest) => $messageRequest->getRequest() === $request
            ))->willReturn(null);

        $this->mockResponseHandler
            ->expects($this->never())
            ->method('handleResponse');

        self::assertNull($this->subject->send($request));
    }

    public function test_it_should_throw_a_LDAP_specific_connection_exception_if_the_response_handler_throws_a_socket_exception(): void
    {
        $request = new DeleteRequest('cn=foo');
        $messageResponse = new LdapMessageResponse(1, new DeleteResponse(0));

        $this->mockRequestHandler
            ->expects($this->once())
            ->method('handleRequest')
            ->with($this->callback(
                fn (LdapMessageRequest $messageRequest) => $messageRequest->getRequest() === $request
            ))->willReturn($messageResponse);

        $this->mockResponseHandler
            ->expects($this->once())
            ->method('handleResponse')
            ->willThrowException(new \FreeDSx\Socket\Exception\ConnectionException('foo'));

        $this->expectException(ConnectionException::class);

        $this->subject->send($request);
    }
}
