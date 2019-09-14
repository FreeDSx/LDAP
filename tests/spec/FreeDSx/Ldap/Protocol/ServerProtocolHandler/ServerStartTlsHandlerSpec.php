<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerStartTlsHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PhpSpec\ObjectBehavior;

class ServerStartTlsHandlerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ServerStartTlsHandler::class);
    }

    function it_should_handle_a_start_tls_request(ServerQueue $queue, TokenInterface $token, RequestHandlerInterface $dispatcher)
    {
        $queue->isEncrypted()->willReturn(false);

        $queue->encrypt()->shouldBeCalled();
        $queue->sendMessage(new LdapMessageResponse(
            1,
            new ExtendedResponse(
                new LdapResult(0),
                ExtendedRequest::OID_START_TLS
            )
        ))->shouldBeCalled();

        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));
        $this->handleRequest($startTls, $token, $dispatcher, $queue, ['ssl_cert' => 'foo']);
    }

    function it_should_send_back_an_error_if_the_queue_is_already_encrypted(ServerQueue $queue, TokenInterface $token, RequestHandlerInterface $dispatcher)
    {
        $queue->isEncrypted()->willReturn(true);

        $queue->encrypt()->shouldNotBeCalled();
        $queue->sendMessage(new LdapMessageResponse(
            1,
            new ExtendedResponse(
                new LdapResult(ResultCode::OPERATIONS_ERROR, '', 'The current LDAP session is already encrypted.'),
                ExtendedRequest::OID_START_TLS
            )
        ))->shouldBeCalled();

        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));
        $this->handleRequest($startTls, $token, $dispatcher, $queue, ['ssl_cert' => 'foo']);
    }

    function it_should_send_back_an_error_if_encryption_is_not_supported(ServerQueue $queue, TokenInterface $token, RequestHandlerInterface $dispatcher)
    {
        $queue->isEncrypted()->willReturn(false);

        $queue->encrypt()->shouldNotBeCalled();
        $queue->sendMessage(new LdapMessageResponse(
            1,
            new ExtendedResponse(
                new LdapResult(ResultCode::PROTOCOL_ERROR),
                ExtendedRequest::OID_START_TLS
            )
        ))->shouldBeCalled();

        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));
        $this->handleRequest($startTls, $token, $dispatcher, $queue, []);
    }
}
