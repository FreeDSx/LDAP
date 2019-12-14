<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientProtocolContext;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientBasicHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ResponseHandlerInterface;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientBasicHandlerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ClientBasicHandler::class);
    }

    function it_should_implement_ResponseHandlerInterface()
    {
        $this->shouldBeAnInstanceOf(ResponseHandlerInterface::class);
    }

    function it_should_implement_RequestHandlerInterface()
    {
        $this->shouldBeAnInstanceOf(RequestHandlerInterface::class);
    }

    function it_should_handle_a_request_and_return_a_response(ClientProtocolContext $context, ClientQueue $queue, ClientProtocolHandler $protocolHandler)
    {
        $context->messageToSend()->willReturn(new LdapMessageRequest(1, new DeleteRequest('cn=foo')));
        $context->getQueue()->willReturn($queue);

        $queue->sendMessage(Argument::type(LdapMessageRequest::class))->shouldBeCalledOnce();
        $queue->getMessage(1)->willReturn(
            new LdapMessageResponse(1, new DeleteResponse(0))
        );

        $this->handleRequest($context)->shouldBeAnInstanceOf(
            LdapMessageResponse::class
        );
    }

    function it_should_handle_a_response(ClientQueue $queue)
    {
        $messageRequest = new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar'));
        $messageFrom = new LdapMessageResponse(1, new BindResponse(new LdapResult(0)));

        $options = [];
        $this->handleResponse($messageRequest, $messageFrom, $queue, $options)->shouldBeEqualTo($messageFrom);
    }

    function it_should_handle_a_response_with_non_error_codes(ClientQueue $queue)
    {
        $options = [];
        $messageRequest = new LdapMessageRequest(1, new CompareRequest('foo', new EqualityFilter('foo', 'bar') ));
        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_FALSE));

        $this->handleResponse($messageRequest, $messageFrom, $queue, $options)->shouldBeEqualTo($messageFrom);

        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_TRUE));

        $this->handleResponse($messageRequest, $messageFrom, $queue, $options)->shouldBeEqualTo($messageFrom);

        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::REFERRAL));

        $this->handleResponse($messageRequest, $messageFrom, $queue, $options)->shouldBeEqualTo($messageFrom);
    }

    function it_should_throw_an_operation_exception_on_errors(ClientQueue $queue)
    {
        $messageRequest = new LdapMessageRequest(1, new CompareRequest('foo', new EqualityFilter('foo', 'bar') ));
        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_FALSE));

        $options = [];
        $this->handleResponse($messageRequest, $messageFrom, $queue, $options)->shouldBeEqualTo($messageFrom);
    }

    function it_should_throw_a_specific_bind_exception_for_a_bind_response(ClientQueue $queue)
    {
        $messageRequest = new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar'));
        $messageFrom = new LdapMessageResponse(1, new BindResponse(new LdapResult(ResultCode::INVALID_CREDENTIALS, 'foo', 'message')));

        $options = [];
        $this->shouldThrow(new BindException('Unable to bind to LDAP. message', ResultCode::INVALID_CREDENTIALS))->during('handleResponse', [$messageRequest, $messageFrom, $queue, $options]);
    }
}
