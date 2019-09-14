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
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerWhoAmIHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PhpSpec\ObjectBehavior;

class ServerWhoAmIHandlerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ServerWhoAmIHandler::class);
    }

    function it_should_handle_a_who_am_i_when_there_is_a_token_with_a_DN_name(ServerQueue $queue, RequestHandlerInterface $handler)
    {
        $request = new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI));

        $queue->sendMessage(new LdapMessageResponse(
            2,
            new ExtendedResponse(new LdapResult(0), null,'dn:cn=foo,dc=foo,dc=bar')
        ));

        $this->handleRequest(
            $request,
            new BindToken('cn=foo,dc=foo,dc=bar', '12345'),
            $handler,
            $queue,
            []
        );
    }

    function it_should_handle_a_who_am_i_when_there_is_a_token_with_a_non_DN_name(ServerQueue $queue, RequestHandlerInterface $handler)
    {
        $request = new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI));

        $queue->sendMessage(new LdapMessageResponse(
            2,
            new ExtendedResponse(new LdapResult(0), null,'u:foo@bar.local')
        ))->shouldBeCalled();

        $this->handleRequest(
            $request,
            new BindToken('foo@bar.local', '12345'),
            $handler,
            $queue,
            []
        );
    }

    function it_should_handle_a_who_am_i_when_there_is_no_token_yet(ServerQueue $queue, RequestHandlerInterface $handler)
    {
        $request = new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI));

        $queue->getMessage()->willReturn(new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI)), null);
        $queue->sendMessage(new LdapMessageResponse(
            2,
            new ExtendedResponse(new LdapResult(0), null, '')
        ))->shouldBeCalled();

        $this->handleRequest(
            $request,
            new AnonToken(),
            $handler,
            $queue,
            []
        );
    }
}
