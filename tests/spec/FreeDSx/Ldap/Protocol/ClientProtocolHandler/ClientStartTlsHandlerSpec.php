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

use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientStartTlsHandler;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ResponseHandlerInterface;
use PhpSpec\ObjectBehavior;

class ClientStartTlsHandlerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ClientStartTlsHandler::class);
    }

    function it_should_implement_ResponseHandlerInterface()
    {
        $this->shouldBeAnInstanceOf(ResponseHandlerInterface::class);
    }

    function it_should_encrypt_the_queue_if_the_message_response_is_successful(ClientQueue $queue)
    {
        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));
        $response = new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0), ExtendedRequest::OID_START_TLS));

        $queue->encrypt()->shouldBeCalledOnce();
        $this->handleResponse($startTls, $response, $queue, [])->shouldBeAnInstanceOf(LdapMessageResponse::class);
    }

    function it_should_throw_an_exception_if_the_message_response_is_unsuccessful(ClientQueue $queue)
    {
        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));
        $response = new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(ResultCode::UNAVAILABLE_CRITICAL_EXTENSION), ExtendedRequest::OID_START_TLS));

        $queue->encrypt(true)->shouldNotBeCalled();
        $this->shouldThrow(ConnectionException::class)->during('handleResponse', [$startTls, $response, $queue, []]);
    }
}
