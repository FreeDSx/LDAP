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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\Exception\SkipReferralException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\LdapUrl;
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
use FreeDSx\Ldap\ReferralChaserInterface;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Tcp\ClientMessageQueue;
use FreeDSx\Ldap\Tcp\Socket;
use FreeDSx\Ldap\Tcp\SocketPool;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientProtocolHandlerSpec extends ObjectBehavior
{
    function let(SocketPool $pool, Socket $client, ClientMessageQueue $queue)
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

    function it_should_throw_an_exception_on_referrals($queue, $pool)
    {
        $this->beConstructedWith(['referral' => 'throw'], $queue, $pool);
        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', 'foo', new LdapUrl('foo'))));

        $this->shouldThrow(ReferralException::class)->during('send', [new DeleteRequest('foo')]);
    }

    function it_should_follow_referrals_with_a_referral_chaser_if_specified(ReferralChaserInterface $chaser, $queue, $pool, LdapClient $ldapClient)
    {
        $this->beConstructedWith(['referral' => 'follow', 'referral_limit' => 10, 'referral_chaser' => $chaser], $queue, $pool);
        $chaser->client(Argument::any())->willReturn($ldapClient);
        $bind = new SimpleBindRequest('foo', 'bar');
        $chaser->chase(Argument::any(), Argument::any(), Argument::any())->willReturn($bind);
        $ldapClient->send($bind)->shouldBeCalled()->willReturn(null);

        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'))));
        $message = new LdapMessageResponse(2, new DeleteResponse(0));
        $ldapClient->send(new DeleteRequest('foo'))->shouldBeCalled()->willReturn($message);
        $this->send(new DeleteRequest('foo'))->shouldBeLike($message);
    }

    function it_should_throw_an_exception_if_the_referral_limit_is_reached(ReferralChaserInterface $chaser, $queue, $pool)
    {
        $this->beConstructedWith(['referral' => 'follow', 'referral_limit' => -1, 'referral_chaser' => $chaser], $queue, $pool);

        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'))));
        $this->shouldThrow(OperationException::class)->during('send', [new DeleteRequest('foo')]);
    }

    function it_should_throw_an_exception_if_all_referrals_have_been_tried_and_follow_is_specified(ReferralChaserInterface $chaser, $queue, $pool)
    {
        $this->beConstructedWith(['referral' => 'follow', 'referral_limit' => 10, 'referral_chaser' => $chaser], $queue, $pool);
        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'))));

        $chaser->chase(Argument::any(), Argument::any(), Argument::any())->willThrow(new SkipReferralException());
        $this->shouldThrow(OperationException::class)->during('send', [new DeleteRequest('foo')]);
    }

    function it_should_continue_to_the_next_referral_if_a_connection_exception_is_thrown(ReferralChaserInterface $chaser, $queue, $pool, LdapClient $ldapClient)
    {
        $this->beConstructedWith(['referral' => 'follow', 'referral_limit' => 10, 'referral_chaser' => $chaser], $queue, $pool);
        $chaser->client(Argument::any())->willReturn($ldapClient);
        $bind = new SimpleBindRequest('foo', 'bar');
        $chaser->chase(Argument::any(), Argument::any(), Argument::any())->willReturn($bind);
        $ldapClient->send($bind)->shouldBeCalled()->willThrow(new ConnectionException(), 1);
        $ldapClient->send($bind)->shouldBeCalled()->willReturn(null, 2);

        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'), new LdapUrl('bar'))));
        $message = new LdapMessageResponse(2, new DeleteResponse(0));
        $ldapClient->send(new DeleteRequest('foo'))->shouldBeCalled()->willReturn($message);
        $this->send(new DeleteRequest('foo'))->shouldBeLike($message);
    }

    function it_should_continue_to_the_next_referral_if_an_operation_exception_with_a_referral_result_code_is_thrown(ReferralChaserInterface $chaser, $queue, $pool, LdapClient $ldapClient)
    {
        $this->beConstructedWith(['referral' => 'follow', 'referral_limit' => 10, 'referral_chaser' => $chaser], $queue, $pool);
        $chaser->client(Argument::any())->willReturn($ldapClient);
        $bind = new SimpleBindRequest('foo', 'bar');
        $chaser->chase(Argument::any(), Argument::any(), Argument::any())->willReturn($bind);
        $ldapClient->send($bind)->shouldBeCalled()->willReturn(null);

        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'), new LdapUrl('bar'))));
        $message = new LdapMessageResponse(2, new DeleteResponse(0));
        $ldapClient->send(new DeleteRequest('foo'))->shouldBeCalled()->willThrow(new OperationException('fail', ResultCode::REFERRAL), 1);
        $ldapClient->send(new DeleteRequest('foo'))->shouldBeCalled()->willReturn($message, 2);
        $this->send(new DeleteRequest('foo'))->shouldBeLike($message);
    }

    function it_should_not_bind_on_the_referral_client_initially_if_the_referral_is_for_a_bind_request(ReferralChaserInterface $chaser, $queue, $pool, LdapClient $ldapClient)
    {
        $this->beConstructedWith(['referral' => 'follow', 'referral_limit' => 10, 'referral_chaser' => $chaser], $queue, $pool);
        $chaser->client(Argument::any())->willReturn($ldapClient);
        $chaser->chase(Argument::any(), Argument::any(), Argument::any())->willReturn(new SimpleBindRequest('foo', 'bar'));
        $ldapClient->send(Argument::any())->shouldBeCalledTimes(1);

        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new BindResponse(new LdapResult(ResultCode::REFERRAL, '', '', new LdapUrl('foo')))));
        $message = new LdapMessageResponse(1, new BindResponse(new LdapResult(0)));
        $ldapClient->send(new SimpleBindRequest('foo', 'bar'))->shouldBeCalled()->willReturn($message);
        $this->send(new SimpleBindRequest('foo', 'bar'))->shouldBeLike($message);
    }
}
