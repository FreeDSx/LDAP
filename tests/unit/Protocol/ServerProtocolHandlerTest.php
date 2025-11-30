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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Exception\ConnectionException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

final class ServerProtocolHandlerTest extends TestCase
{
    private ServerProtocolHandler $subject;

    private ServerQueue&MockObject $mockQueue;

    private ServerProtocolHandlerFactory&MockObject $mockProtocolHandlerFactory;

    private LoggerInterface&MockObject $mockLogger;

    private Authenticator&MockObject $mockAuthenticator;

    private ServerProtocolHandler\ServerProtocolHandlerInterface&MockObject $mockProtocolHandler;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockProtocolHandlerFactory = $this->createMock(ServerProtocolHandlerFactory::class);
        $this->mockLogger = $this->createMock(LoggerInterface::class);
        $this->mockAuthenticator = $this->createMock(Authenticator::class);
        $this->mockProtocolHandler = $this->createMock(ServerProtocolHandler\ServerProtocolHandlerInterface::class);

        $this->mockQueue
            ->method('isConnected')
            ->willReturn(true);
        $this->mockQueue
            ->method('isEncrypted')
            ->willReturn(false);

        $this->mockQueue
            ->method('sendMessage')
            ->willReturnSelf();

        $this->mockProtocolHandlerFactory
            ->method('get')
            ->willReturn($this->mockProtocolHandler);

        $this->subject = new ServerProtocolHandler(
            $this->mockQueue,
            $this->mockProtocolHandlerFactory,
            new ServerAuthorization(new ServerOptions()),
            $this->mockAuthenticator,
            $this->mockLogger,
        );
    }

    public function test_it_should_enforce_anonymous_bind_requirements(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->will($this->onConsecutiveCalls(
                new LdapMessageRequest(1, new AnonBindRequest('foo')),
                $this->throwException(new ConnectionException()),
            ));

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(
                    1,
                    new BindResponse(new LdapResult(
                        ResultCode::AUTH_METHOD_UNSUPPORTED,
                        '',
                        'The requested authentication type is not supported.'
                    ))
                )
            ));

        $this->mockProtocolHandlerFactory
            ->expects(self::never())
            ->method('get');

        $this->subject->handle();
    }

    public function test_it_should_not_allow_a_previous_message_ID_from_a_new_request(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->will($this->onConsecutiveCalls(
                new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
                new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_WHOAMI)),
                $this->throwException(new ConnectionException())
            ));

        $this->mockAuthenticator
            ->method('bind')
            ->willReturn(new BindToken('foo', 'bar'));

        $this->mockProtocolHandler
            ->expects($this->never())
            ->method('handleRequest');

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(new LdapMessageResponse(
                0,
                new ExtendedResponse(new LdapResult(
                    ResultCode::PROTOCOL_ERROR,
                    '',
                    'The message ID 1 is not valid.'
                ))
            )));

        $this->subject->handle();
    }

    public function test_it_should_enforce_authentication_requirements(): void
    {
        $this->mockQueue
            ->method('isConnected')
            ->willReturn(true);
        $this->mockQueue
            ->method('getMessage')
            ->will(
                $this->onConsecutiveCalls(
                    new LdapMessageRequest(
                        1,
                        new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true)
                    ),
                    $this->throwException(new ConnectionException())
                )
            );

        $this->mockQueue
            ->expects($this->atLeast(1))
            ->method('sendMessage')
            ->with($this->equalTo(new LdapMessageResponse(
                1,
                new ModifyDnResponse(
                    ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                    'cn=foo,dc=bar',
                    'Authentication required.'
                )
            )))
            ->willReturnSelf();

        $this->mockProtocolHandler
            ->expects($this->never())
            ->method('handleRequest');

        $this->subject->handle();
    }

    public function test_it_should_send_a_notice_of_disconnect_on_a_protocol_exception_from_the_message_queue(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new ProtocolException());

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(0, new ExtendedResponse(
                    new LdapResult(ResultCode::PROTOCOL_ERROR, '', 'The message encoding is malformed.'),
                    ExtendedResponse::OID_NOTICE_OF_DISCONNECTION
                ))
            ));

        $this->subject->handle();
    }

    public function test_it_should_handle_a_socket_exception_from_the_message_queue_and_end_normally(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new ConnectionException("Foo"));

        $this->mockLogger
            ->expects($this->once())
            ->method('log')
            ->with(
                LogLevel::INFO,
                'Ending LDAP client due to client connection issues.',
                $this->anything()
            );

        $this->subject->handle();
    }

    public function test_it_should_send_a_notice_of_disconnect_on_an_encoder_exception_from_the_message_queue(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new EncoderException());

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(0, new ExtendedResponse(
                    new LdapResult(ResultCode::PROTOCOL_ERROR, '', 'The message encoding is malformed.'),
                    ExtendedResponse::OID_NOTICE_OF_DISCONNECTION
                ))
            ));

        $this->subject->handle();
    }

    public function test_it_should_not_allow_a_message_with_an_ID_of_zero(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->will($this->onConsecutiveCalls(
                new LdapMessageRequest(
                    0,
                    new ExtendedRequest(ExtendedRequest::OID_START_TLS)
                ),
                $this->throwException(new ConnectionException())
            ));

        $this->mockQueue
            ->expects($this->atLeast(1))
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(0, new ExtendedResponse(new LdapResult(
                    ResultCode::PROTOCOL_ERROR,
                    '',
                    'The message ID 0 cannot be used in a client request.'
                )))
            ));

        $this->subject->handle();
    }

    public function test_it_should_send_a_bind_request_to_the_bind_request_handler(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->will($this->onConsecutiveCalls(
                new LdapMessageRequest(
                    1,
                    new SimpleBindRequest('foo@bar', 'bar')
                ),
                $this->throwException(new ConnectionException())
            ));

        $this->mockAuthenticator
            ->expects($this->once())
            ->method('bind')
            ->willReturn(new BindToken('foo@bar', 'bar'));

        $this->mockProtocolHandler
            ->expects($this->never())
            ->method('handleRequest');

        $this->subject->handle();
    }

    public function test_it_should_handle_operation_errors_thrown_from_the_request_handlers(): void
    {
        $this->mockQueue
            ->method('isConnected')
            ->will($this->onConsecutiveCalls(true, false));

        $this->mockQueue
            ->method('getMessage')
            ->will($this->onConsecutiveCalls(
                new LdapMessageRequest(1, new SimpleBindRequest('foo@bar', 'bar')),
                new LdapMessageRequest(2, new ModifyRequest('cn=foo,dc=bar')),
                $this->throwException(new ConnectionException()),
            ));

        $this->mockAuthenticator
            ->expects($this->once())
            ->method('bind')
            ->willReturn(new BindToken('foo@bar', 'bar'));

        $this->mockProtocolHandler
            ->expects($this->once())
            ->method('handleRequest')
            ->willThrowException(new OperationException(
                'Foo.',
                ResultCode::CONFIDENTIALITY_REQUIRED
            ));

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(
                    2,
                    new ModifyResponse(
                        ResultCode::CONFIDENTIALITY_REQUIRED,
                        'cn=foo,dc=bar',
                        'Foo.'
                    )
                )
            ));

        $this->subject->handle();
    }

    public function test_it_should_send_a_notice_of_disconnect_and_close_the_queue_on_shutdown(): void
    {
        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(0, new ExtendedResponse(
                    new LdapResult(ResultCode::UNAVAILABLE, '', 'The server is shutting down.'),
                    ExtendedResponse::OID_NOTICE_OF_DISCONNECTION
                ))
            ));

        $this->mockQueue
            ->expects($this->once())
            ->method('close');

        $this->subject->shutdown();
    }
}
