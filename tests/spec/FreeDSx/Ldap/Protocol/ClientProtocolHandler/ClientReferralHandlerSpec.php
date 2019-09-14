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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\Exception\SkipReferralException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientReferralHandler;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\ReferralChaserInterface;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientReferralHandlerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ClientReferralHandler::class);
    }

    function it_should_throw_an_exception_on_referrals(ClientQueue $queue)
    {
        $response = new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', 'foo', new LdapUrl('foo')));
        $request = new LdapMessageRequest(1, new DeleteRequest('cn=foo'));

        $this->shouldThrow(ReferralException::class)->during('handleResponse', [$request, $response, $queue, ['referral' => 'throw']]);
    }

    function it_should_follow_referrals_with_a_referral_chaser_if_specified(ReferralChaserInterface $chaser, ClientQueue $queue, LdapClient $ldapClient)
    {
        $chaser->client(Argument::any())->willReturn($ldapClient);
        $bind = new SimpleBindRequest('foo', 'bar');
        $chaser->chase(Argument::any(), Argument::any(), Argument::any())->willReturn($bind);
        $ldapClient->send($bind)->shouldBeCalled()->willReturn(null);

        $message = new LdapMessageResponse(2, new DeleteResponse(0));
        $ldapClient->send(new DeleteRequest('foo'))->shouldBeCalled()->willReturn($message);

        $this->handleResponse(
            new LdapMessageRequest(2, new DeleteRequest('foo')),
            new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'))),
            $queue,
            ['referral' => 'follow', 'referral_limit' => 10, 'referral_chaser' => $chaser]
        )->shouldBeLike($message);
    }

    function it_should_throw_an_exception_if_the_referral_limit_is_reached(ReferralChaserInterface $chaser, ClientQueue $queue)
    {
        $this->shouldThrow(new OperationException('The referral limit of -1 has been reached.'))->during('handleResponse', [
            new LdapMessageRequest(2, new DeleteRequest('foo')),
            new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'))),
            $queue,
            ['referral' => 'follow', 'referral_limit' => -1, 'referral_chaser' => $chaser]
        ]);
    }

    function it_should_throw_an_exception_if_all_referrals_have_been_tried_and_follow_is_specified(ReferralChaserInterface $chaser, ClientQueue $queue)
    {
        $chaser->chase(Argument::any(), Argument::any(), Argument::any())->willThrow(new SkipReferralException());

        $this->shouldThrow(new OperationException('All referral attempts have been exhausted. ', ResultCode::REFERRAL))->during('handleResponse', [
            new LdapMessageRequest(2, new DeleteRequest('foo')),
            new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'))),
            $queue,
            ['referral' => 'follow', 'referral_limit' => 10, 'referral_chaser' => $chaser]
        ]);
    }

    function it_should_continue_to_the_next_referral_if_a_connection_exception_is_thrown(ReferralChaserInterface $chaser, ClientQueue $queue, LdapClient $ldapClient)
    {
        $chaser->client(Argument::any())->willReturn($ldapClient);
        $bind = new SimpleBindRequest('foo', 'bar');

        $chaser->chase(Argument::any(), Argument::any(), Argument::any())->willReturn($bind);

        $ldapClient->send($bind)->shouldBeCalled()->willThrow(new ConnectionException(), 1);
        $ldapClient->send($bind)->shouldBeCalled()->willReturn(null, 2);

        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'), new LdapUrl('bar'))));
        $message = new LdapMessageResponse(2, new DeleteResponse(0));
        $ldapClient->send(new DeleteRequest('foo'))->shouldBeCalled()->willReturn($message);

        $this->handleResponse(
            new LdapMessageRequest(1, new DeleteRequest('foo')),
            new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'))),
            $queue,
            ['referral' => 'follow', 'referral_limit' => 10, 'referral_chaser' => $chaser]
        )->shouldBeLike($message);
    }

    function it_should_continue_to_the_next_referral_if_an_operation_exception_with_a_referral_result_code_is_thrown(ReferralChaserInterface $chaser, ClientQueue $queue, LdapClient $ldapClient)
    {
        $chaser->client(Argument::any())->willReturn($ldapClient);
        $bind = new SimpleBindRequest('foo', 'bar');
        $chaser->chase(Argument::any(), Argument::any(), Argument::any())->willReturn($bind);
        $ldapClient->send($bind)->shouldBeCalled()->willReturn(null);

        $queue->getMessage(1)->willReturn(new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'), new LdapUrl('bar'))));
        $message = new LdapMessageResponse(2, new DeleteResponse(0));
        $ldapClient->send(new DeleteRequest('foo'))->shouldBeCalled()->willThrow(new OperationException('fail', ResultCode::REFERRAL), 1);
        $ldapClient->send(new DeleteRequest('foo'))->shouldBeCalled()->willReturn($message, 2);

        $this->handleResponse(
            new LdapMessageRequest(1, new DeleteRequest('foo')),
            new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo'))),
            $queue,
            ['referral' => 'follow', 'referral_limit' => 10, 'referral_chaser' => $chaser]
        )->shouldBeLike($message);
    }

    function it_should_not_bind_on_the_referral_client_initially_if_the_referral_is_for_a_bind_request(ReferralChaserInterface $chaser, ClientQueue $queue, LdapClient $ldapClient)
    {
        $chaser->client(Argument::any())->willReturn($ldapClient);
        $chaser->chase(Argument::any(), Argument::any(), Argument::any())->willReturn(new SimpleBindRequest('foo', 'bar'));
        $ldapClient->send(Argument::any())->shouldBeCalledTimes(1);

        $message = new LdapMessageResponse(1, new BindResponse(new LdapResult(0)));
        $ldapClient->send(new SimpleBindRequest('foo', 'bar'))->shouldBeCalled()->willReturn($message);

        $this->handleResponse(
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageResponse(1, new BindResponse(new LdapResult(ResultCode::REFERRAL, '', '', new LdapUrl('foo')))),
            $queue,
            [
                'referral' => 'follow',
                'referral_limit' => 10,
                'referral_chaser' => $chaser,
            ]
        )->shouldBeLike($message);
    }
}
