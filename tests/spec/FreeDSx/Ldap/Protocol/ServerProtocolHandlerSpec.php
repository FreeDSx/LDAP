<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol;

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
use FreeDSx\Ldap\Protocol\Factory\ServerBindHandlerFactory;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ServerProtocolHandlerSpec extends ObjectBehavior
{
    function let(ServerQueue $queue, ServerProtocolHandlerFactory $protocolHandlerFactory, ServerBindHandlerFactory $bindHandlerFactory, RequestHandlerInterface $dispatcher, ServerProtocolHandler\BindHandlerInterface $bindHandler, ServerProtocolHandler\ServerProtocolHandlerInterface $protocolHandler)
    {
        $queue->close()->hasReturnVoid();
        $queue->isConnected()->willReturn(true);
        $queue->isEncrypted()->willReturn(false);
        $queue->sendMessage(Argument::any())->willReturn($queue);
        $bindHandlerFactory->get(Argument::any())->willReturn($bindHandler);
        $protocolHandlerFactory->get(Argument::any())->willReturn($protocolHandler);

        $this->beConstructedWith(
            $queue,
            $dispatcher,
            [],
            $protocolHandlerFactory,
            $bindHandlerFactory
        );
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ServerProtocolHandler::class);
    }

    function it_should_enforce_anonymous_bind_requirements(ServerQueue $queue, ServerBindHandlerFactory $bindHandlerFactory)
    {
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new AnonBindRequest('foo')),
            null
        );

        $queue->sendMessage(new LdapMessageResponse(
            1,
            new BindResponse(new LdapResult(
                ResultCode::AUTH_METHOD_UNSUPPORTED,
                '',
                'The requested authentication type is not supported.'
            ))
        ))->shouldBeCalled();
        $bindHandlerFactory->get(Argument::any())->shouldNotBeCalled();

        $this->handle();
    }

    function it_should_not_allow_a_previous_message_ID_from_a_new_request(ServerQueue $queue, ServerProtocolHandler\BindHandlerInterface $bindHandler, ServerProtocolHandler\ServerProtocolHandlerInterface $protocolHandler)
    {
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_WHOAMI)),
            null
        );

        $bindHandler->handleBind(Argument::any(), Argument::any(), Argument::any(), Argument::any())->willReturn(
            new BindToken('foo', 'bar')
        );
        $protocolHandler->handleRequest(Argument::any(), Argument::any(), Argument::any(), Argument::any(), Argument::any())
            ->shouldNotBeCalled();

        $queue->sendMessage(new LdapMessageResponse(
            0,
            new ExtendedResponse(new LdapResult(
                ResultCode::PROTOCOL_ERROR,
                '',
                'The message ID 1 is not valid.'
            ))
        ))->shouldBeCalled();

        $this->handle();
    }

function it_should_enforce_authentication_requirements(ServerQueue $queue, ServerProtocolHandler\ServerProtocolHandlerInterface $protocolHandler)
    {
        $queue->isConnected()->willReturn(true, false);
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(
                1,
                new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true)
            ),
            null
        );

        $queue->sendMessage(new LdapMessageResponse(
            1,
            new ModifyDnResponse(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                'cn=foo,dc=bar',
                'Authentication required.')
        ))->shouldBeCalled()->willReturn($queue);

        $protocolHandler->handleRequest(Argument::any(), Argument::any(), Argument::any(), Argument::any(), Argument::any())
            ->shouldNotBeCalled();

        $this->handle();
    }

    function it_should_send_a_notice_of_disconnect_on_a_protocol_exception_from_the_message_queue(ServerQueue $queue)
    {
        $queue->getMessage()->willThrow(new ProtocolException());

        $queue->sendMessage(new LdapMessageResponse(0, new ExtendedResponse(
            new LdapResult(ResultCode::PROTOCOL_ERROR, '', 'The message encoding is malformed.'),
            ExtendedResponse::OID_NOTICE_OF_DISCONNECTION
        )))->shouldBeCalled();

        $this->handle();
    }

    function it_should_send_a_notice_of_disconnect_on_an_encoder_exception_from_the_message_queue(ServerQueue $queue)
    {
        $queue->getMessage()->willThrow(new EncoderException());

        $queue->sendMessage(new LdapMessageResponse(0, new ExtendedResponse(
            new LdapResult(ResultCode::PROTOCOL_ERROR, '', 'The message encoding is malformed.'),
            ExtendedResponse::OID_NOTICE_OF_DISCONNECTION
        )))->shouldBeCalled();

        $this->handle();
    }

    function it_should_not_allow_a_message_with_an_ID_of_zero(ServerQueue $queue)
    {
        $queue->getMessage()->willReturn(new LdapMessageRequest(0, new ExtendedRequest(ExtendedRequest::OID_START_TLS)), null);

        $queue->sendMessage(new LdapMessageResponse(0, new ExtendedResponse(new LdapResult(
            ResultCode::PROTOCOL_ERROR,
            '',
            'The message ID 0 cannot be used in a client request.'
        ))))->shouldBeCalled();

        $this->handle();
    }

    function it_should_send_a_bind_request_to_the_bind_request_handler(ServerQueue $queue, ServerProtocolHandler\BindHandlerInterface $bindHandler, ServerProtocolHandler\ServerProtocolHandlerInterface $protocolHandler)
    {
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo@bar', 'bar')),
            null
        );

        $bindHandler->handleBind(Argument::any(), Argument::any(), Argument::any(), Argument::any())
            ->shouldBeCalledOnce()
            ->willReturn(new BindToken('foo@bar', 'bar'));
        $protocolHandler->handleRequest(Argument::any(), Argument::any(), Argument::any(), Argument::any(), Argument::any())
            ->shouldNotBeCalled();

        $this->handle();
    }

    function it_should_handle_operation_errors_thrown_from_the_request_handlers(ServerQueue $queue, ServerProtocolHandler\BindHandlerInterface $bindHandler, ServerProtocolHandler\ServerProtocolHandlerInterface $protocolHandler)
    {
        $queue->isConnected()->willReturn(true, false);
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo@bar', 'bar')),
            new LdapMessageRequest(2, new ModifyRequest('cn=foo,dc=bar')),
            null
        );

        $bindHandler->handleBind(Argument::any(), Argument::any(), Argument::any(), Argument::any())
            ->willReturn(new BindToken('foo@bar', 'bar'));

        $protocolHandler->handleRequest(Argument::any(), Argument::any(), Argument::any(), Argument::any(), Argument::any())
            ->shouldBeCalled()
            ->willThrow(new OperationException('Foo.', ResultCode::CONFIDENTIALITY_REQUIRED));

        $queue->sendMessage(new LdapMessageResponse(
            2,
            new ModifyResponse(
                ResultCode::CONFIDENTIALITY_REQUIRED,
                'cn=foo,dc=bar',
                'Foo.'
            )))->shouldBeCalled();

        $this->handle();
    }
}
