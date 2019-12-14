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

use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientExtendedOperationHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientProtocolContext;
use FreeDSx\Ldap\Protocol\Factory\ExtendedResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ResponseHandlerInterface;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientExtendedOperationHandlerSpec extends ObjectBehavior
{
    function let(ExtendedResponseFactory $responseFactory)
    {
        $this->beConstructedWith($responseFactory);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ClientExtendedOperationHandler::class);
    }

    function it_should_implement_ClientResponseHandler()
    {
        $this->shouldBeAnInstanceOf(ResponseHandlerInterface::class);
    }

    function it_should_handle_a_response(ExtendedResponseFactory $responseFactory, ClientQueue $queue)
    {
        $responseFactory->has(Argument::any())->willReturn(false);
        $responseFactory->get(Argument::any(), Argument::any())->shouldNotBeCalled();

        $response = new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0), 'bar', 'foo'));
        $this->handleResponse(
            new LdapMessageRequest(1, new ExtendedRequest('foo', 'bar')),
            $response,
            $queue,
            []
        )->shouldBeEqualTo($response);
    }

    function it_should_handle_an_extended_response_that_has_a_mapped_class(ClientProtocolContext $context, ExtendedResponseFactory $responseFactory, ClientQueue $queue)
    {
        $extendedResponse = new PasswordModifyResponse(new LdapResult(0));
        $responseFactory->has(Argument::any())->willReturn(true);
        $responseFactory->get(Argument::any(), 'foo')->shouldBeCalled()->willReturn($extendedResponse);

        $request = new ExtendedRequest('foo', 'bar');
        $extendedRequest = new LdapMessageRequest(1, $request);
        $response = new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0), 'bar'));
        $queue->getMessage(Argument::any())->willReturn($response);
        $queue->sendMessage($extendedRequest)->shouldBeCalled();

        $context->getRequest()->willReturn($request);
        $context->messageToSend()->willReturn($extendedRequest);
        $context->getQueue()->willReturn($queue);
        $this->handleRequest($context)->getResponse()->shouldBeAnInstanceOf(PasswordModifyResponse::class);
    }
}
