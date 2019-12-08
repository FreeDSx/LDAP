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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ResponseHandlerInterface;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Socket\SocketPool;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientProtocolHandlerSpec extends ObjectBehavior
{
    function let(SocketPool $pool, ClientQueue $queue, ClientProtocolHandlerFactory $protocolHandlerFactory, ResponseHandlerInterface $responseHandler, RequestHandlerInterface $requestHandler)
    {
        $protocolHandlerFactory->forResponse(Argument::any(), Argument::any())->willReturn($responseHandler);
        $protocolHandlerFactory->forRequest(Argument::any())->willReturn($requestHandler);
        $queue->generateId()->willReturn(1);

        $this->beConstructedWith([], $queue, $pool, $protocolHandlerFactory);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ClientProtocolHandler::class);
    }

    function it_should_close_the_queue_on_a_disconnect_notice_and_throw_a_connection_exception(RequestHandlerInterface $requestHandler, ClientQueue $queue)
    {
        $requestHandler->handleRequest(Argument::any(), Argument::any(), Argument::any())->willThrow(new UnsolicitedNotificationException('foo', 0, null, ExtendedResponse::OID_NOTICE_OF_DISCONNECTION ));

        $queue->close()->shouldBeCalledOnce();
        $this->shouldThrow(ConnectionException::class)->during('send', [new DeleteRequest('foo')]);
    }

    function it_should_throw_a_ldap_specific_connection_exception_on_socket_issues(RequestHandlerInterface $requestHandler, ClientQueue $queue)
    {
        $requestHandler->handleRequest(Argument::any(), Argument::any(), Argument::any())->willThrow(new \FreeDSx\Socket\Exception\ConnectionException('foo'));

        $this->shouldThrow(ConnectionException::class)->during('send', [new DeleteRequest('foo')]);
    }

    function it_should_send_a_request_and_handle_a_response(RequestHandlerInterface $requestHandler, ResponseHandlerInterface $responseHandler, ClientQueue $queue)
    {
        $request = new DeleteRequest('cn=foo');
        $messageResponse = new LdapMessageResponse(1, new DeleteResponse(0));
        $messageRequest = new LdapMessageRequest(1, $request);

        $requestHandler->handleRequest(Argument::that(function (ClientProtocolHandler\ClientProtocolContext $context) use ($request) {
            return $context->getRequest() === $request && $context->getOptions() === [];
        }))->shouldBeCalledOnce()
            ->willReturn($messageResponse);
        $responseHandler->handleResponse($messageRequest, $messageResponse, $queue, [])->shouldBeCalledOnce()
            ->willReturn($messageResponse);

        $this->send($request)->shouldBeLike($messageResponse);
    }

    function it_should_return_null_if_no_response_was_returned(ResponseHandlerInterface $responseHandler, RequestHandlerInterface $requestHandler, ClientQueue $queue)
    {
        $request = new UnbindRequest();
        $messageRequest = new LdapMessageRequest(1, $request);

        $requestHandler->handleRequest(Argument::that(function (ClientProtocolHandler\ClientProtocolContext $context) use ($request) {
            return $context->getRequest() === $request;
        }))->shouldBeCalledOnce()
            ->willReturn(null);
        $responseHandler->handleResponse(Argument::any(), Argument::any(), Argument::any(), [])->shouldNotBeCalled();

        $this->send($request)->shouldBeEqualTo(null);
    }

    function it_should_throw_a_LDAP_specific_connection_exception_if_the_response_handler_throws_a_socket_exception(ResponseHandlerInterface $responseHandler, RequestHandlerInterface $requestHandler, ClientQueue $queue)
    {
        $request = new DeleteRequest('cn=foo');
        $messageResponse = new LdapMessageResponse(1, new DeleteResponse(0));
        $messageRequest = new LdapMessageRequest(1, $request);

        $requestHandler->handleRequest(Argument::that(function (ClientProtocolHandler\ClientProtocolContext $context) use ($request) {
            return $request === $context->getRequest();
        })
        )->shouldBeCalledOnce()
            ->willReturn($messageResponse);
        $responseHandler->handleResponse($messageRequest, $messageResponse, $queue, [])->shouldBeCalledOnce()
            ->willThrow(new \FreeDSx\Socket\Exception\ConnectionException('foo'));

        $this->shouldThrow(ConnectionException::class)->during('send', [$request]);
    }

    function it_should_fetch_the_root_dse(RequestHandlerInterface $requestHandler, ResponseHandlerInterface $responseHandler, ClientQueue $queue)
    {
        $request = Operations::read('', 'supportedSaslMechanisms', 'supportedControl', 'supportedLDAPVersion');
        $messageResponse = new LdapMessageResponse(1, new SearchResponse(new LdapResult(0), new Entries(new Entry(new Dn('')))));
        $messageRequest = new LdapMessageRequest(1, $request);

        $requestHandler->handleRequest(Argument::that(function (ClientProtocolHandler\ClientProtocolContext $context) use ($request) {
            return $context->getRequest() instanceof SearchRequest && $request->getFilter()->toString() === '(objectClass=*)';
        }))->shouldBeCalledOnce()
            ->willReturn($messageResponse);
        $responseHandler->handleResponse($messageRequest, $messageResponse, $queue, [])->shouldBeCalledOnce()
            ->willReturn($messageResponse);

        $this->fetchRootDse()->shouldBeLike(new Entry(new Dn('')));
    }
}
