<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Tcp;

use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Tcp\ClientMessageQueue;
use FreeDSx\Ldap\Tcp\Socket;
use PhpSpec\ObjectBehavior;

class ClientMessageQueueSpec extends ObjectBehavior
{
    function let(Socket $tcp)
    {
        $this->beConstructedWith($tcp);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ClientMessageQueue::class);
    }

    function it_should_return_a_single_message_on_tcp_read($tcp)
    {
        $encoder = new LdapEncoder();
        $message = new LdapMessageResponse(1, new DeleteResponse(0, 'dc=foo,dc=bar', ''));

        $tcp->read()->willReturn($encoder->encode($message->toAsn1()));
        $tcp->read(false)->shouldBeCalled()->willReturn(false);

        $this->getMessage()->shouldBeLike($message);
    }

    function it_should_throw_an_exception_on_an_unsolicited_message($tcp)
    {
        $encoder = new LdapEncoder();
        $message = new LdapMessageResponse(0, new ExtendedResponse(new LdapResult(0, ''), ExtendedResponse::OID_NOTICE_OF_DISCONNECTION));

        $tcp->read()->willReturn($encoder->encode($message->toAsn1()));
        $tcp->read(false)->shouldBeCalled()->willReturn(false);

        $this->shouldThrow(UnsolicitedNotificationException::class)->duringGetMessage();
    }

    function it_should_throw_an_exception_for_a_message_whose_ID_is_unexpected($tcp)
    {
        $encoder = new LdapEncoder();
        $message = new LdapMessageResponse(99, new DeleteResponse(0, 'dc=foo'));

        $tcp->read()->willReturn($encoder->encode($message->toAsn1()));
        $tcp->read(false)->shouldBeCalled()->willReturn(false);

        $this->shouldThrow(ProtocolException::class)->duringGetMessage(1);
    }

    function it_should_continue_on_during_partial_PDUs($tcp)
    {
        $encoder = new LdapEncoder();
        $message = new LdapMessageResponse(1, new DeleteResponse(0, 'dc=foo,dc=bar', ''));

        $encoded = $encoder->encode($message->toAsn1());
        $part1 = substr($encoded, 0, 10);
        $part2 = substr($encoded, 10);
        $tcp->read()->willReturn($part1, $part2);
        $tcp->read(false)->shouldBeCalled()->willReturn(false);

        $this->getMessage()->shouldBeLike($message);
    }

    function it_should_throw_an_exception_on_get_message_when_there_is_none($tcp)
    {
        $tcp->read()->willReturn(false);
        $this->shouldThrow(ConnectionException::class)->duringGetMessage();
    }
}
