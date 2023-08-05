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

namespace spec\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\ClientOptions;
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
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientBasicHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientProtocolContext;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ResponseHandlerInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientBasicHandlerSpec extends ObjectBehavior
{
    public function let(ClientQueue $queue): void
    {
        $this->beConstructedWith($queue);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ClientBasicHandler::class);
    }

    public function it_should_implement_ResponseHandlerInterface(): void
    {
        $this->shouldBeAnInstanceOf(ResponseHandlerInterface::class);
    }

    public function it_should_implement_RequestHandlerInterface(): void
    {
        $this->shouldBeAnInstanceOf(RequestHandlerInterface::class);
    }

    public function it_should_handle_a_request_and_return_a_response(
        ClientProtocolContext $context,
        ClientQueue $queue,
    ): void {
        $context->messageToSend()->willReturn(new LdapMessageRequest(1, new DeleteRequest('cn=foo')));

        $queue->sendMessage(Argument::type(LdapMessageRequest::class))->shouldBeCalledOnce();
        $queue->getMessage(1)->willReturn(
            new LdapMessageResponse(1, new DeleteResponse(0))
        );

        $this->handleRequest($context)->shouldBeAnInstanceOf(
            LdapMessageResponse::class
        );
    }

    public function it_should_handle_a_response(ClientQueue $queue): void
    {
        $messageRequest = new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar'));
        $messageFrom = new LdapMessageResponse(1, new BindResponse(new LdapResult(0)));

        $this->handleResponse(
            $messageRequest,
            $messageFrom,
        )->shouldBeEqualTo($messageFrom);
    }

    public function it_should_handle_a_response_with_non_error_codes(): void
    {
        $messageRequest = new LdapMessageRequest(1, new CompareRequest('foo', new EqualityFilter('foo', 'bar')));
        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_FALSE));

        $this->handleResponse(
            $messageRequest,
            $messageFrom
        )->shouldBeEqualTo($messageFrom);

        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_TRUE));

        $this->handleResponse(
            $messageRequest,
            $messageFrom
        )->shouldBeEqualTo($messageFrom);

        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::REFERRAL));

        $this->handleResponse(
            $messageRequest,
            $messageFrom
        )->shouldBeEqualTo($messageFrom);
    }

    public function it_should_throw_an_operation_exception_on_errors(): void
    {
        $messageRequest = new LdapMessageRequest(1, new CompareRequest('foo', new EqualityFilter('foo', 'bar')));
        $messageFrom = new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_FALSE));

        $this->handleResponse(
            $messageRequest,
            $messageFrom,
        )->shouldBeEqualTo($messageFrom);
    }

    public function it_should_throw_a_specific_bind_exception_for_a_bind_response(): void
    {
        $messageRequest = new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar'));
        $messageFrom = new LdapMessageResponse(1, new BindResponse(new LdapResult(ResultCode::INVALID_CREDENTIALS, 'foo', 'message')));

        $this->shouldThrow(new BindException(
            'Unable to bind to LDAP. message',
            ResultCode::INVALID_CREDENTIALS
        ))->during(
            'handleResponse',
            [
                $messageRequest,
                $messageFrom,
            ]
        );
    }
}
