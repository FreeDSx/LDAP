<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Tcp\ClientMessageQueue;
use FreeDSx\Ldap\Tcp\Socket;
use FreeDSx\Ldap\Tcp\TcpPool;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientProtocolHandlerSpec extends ObjectBehavior
{
    function let(TcpPool $pool, Socket $client, ClientMessageQueue $queue)
    {
        $pool->connect()->willReturn($client);
        $this->beConstructedWith([], $queue, $pool);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ClientProtocolHandler::class);
    }

    function it_should_handle_a_bind_request($queue)
    {
        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new BindResponse(new LdapResult(0, 'foo'))));

        $this->send(new SimpleBindRequest('foo', 'bar'));
    }

    function it_should_throw_a_bind_exception_on_a_bind_failure($queue)
    {
        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new BindResponse(new LdapResult(49, 'foo'))));

        $this->shouldThrow(BindException::class)->during('send', [new SimpleBindRequest('foo', 'bar')]);
    }
    function it_should_handle_a_start_tls_request($client, $queue)
    {
        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0, ''), ExtendedRequest::OID_START_TLS)));
        $client->write(Argument::any())->willReturn(null);

        $client->encrypt(true)->shouldBeCalled();
        $this->send(new ExtendedRequest(ExtendedRequest::OID_START_TLS))->shouldBeEqualTo(null);
    }

    function it_should_handle_a_search_request($queue)
    {
        $queue->getMessages(1)->willReturn([
            new LdapMessageResponse(1, new SearchResultEntry(Entry::create('foo'))),
            new LdapMessageResponse(1, new SearchResultEntry(Entry::create('bar'))),
            new LdapMessageResponse(1, new SearchResultDone(0, ''))
        ]);

        $this->send((new SearchRequest(new EqualityFilter('foo', 'bar')))->base('foo'))->shouldBeLike(
            new LdapMessageResponse(1,
                new SearchResponse(
                    new LdapResult(0, ''),
                    new Entries(Entry::create('foo'), Entry::create('bar'))
                )
            )
        );
    }

    function it_should_handle_an_unbind_request($queue, $client)
    {
        $client->write(Argument::any())->willReturn(null);
        $queue->getMessage(Argument::any())->shouldNotBeCalled();
        $client->close()->shouldBeCalled();

        $this->send(new UnbindRequest())->shouldBeNull();
    }

    function it_should_handle_an_extended_response_that_has_a_mapped_class($queue)
    {
        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0, ''))));

        $this->send(new PasswordModifyRequest())->shouldBeLike(new LdapMessageResponse(1, new PasswordModifyResponse(new LdapResult(0, ''))));
    }

    function it_should_close_the_tcp_socket_on_a_disconnect_notice_and_throw_a_connection_exception($queue, $client)
    {
        $queue->getMessage(Argument::any())->willThrow(new UnsolicitedNotificationException('foo', 0, null, ExtendedResponse::OID_NOTICE_OF_DISCONNECTION));
        $client->write(Argument::any())->willReturn(null);
        $client->close()->shouldBeCalled();

        $this->shouldThrow(ConnectionException::class)->during('send', [new DeleteRequest('foo')]);
    }

    function it_should_not_throw_an_exception_if_specified($queue)
    {
        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new DeleteResponse(ResultCode::INVALID_DN_SYNTAX, 'foo')));

        $this->shouldThrow(ProtocolException::class)->during('send', [new DeleteRequest('foo')]);
    }
}
