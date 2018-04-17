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
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Tcp\ServerMessageQueue;
use FreeDSx\Ldap\Tcp\Socket;
use PhpSpec\ObjectBehavior;

class ServerMessageQueueSpec extends ObjectBehavior
{
    function let(Socket $tcp)
    {
        $this->beConstructedWith($tcp);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ServerMessageQueue::class);
    }

    function it_should_continue_on_during_partial_PDUs($tcp)
    {
        $encoder = new LdapEncoder();
        $message = new LdapMessageRequest(1, new DeleteRequest('dc=foo,dc=bar'));

        $encoded = $encoder->encode($message->toAsn1());
        $part1 = substr($encoded, 0, 10);
        $part2 = substr($encoded, 10);
        $tcp->read()->willReturn($part1, $part2);
        $tcp->read(false)->shouldBeCalled()->willReturn(false);

        $this->getMessage()->shouldBeLike($message);
    }

    function it_should_return_a_single_message_on_tcp_read($tcp)
    {
        $encoder = new LdapEncoder();
        $message = new LdapMessageRequest(1, new DeleteRequest('dc=foo,dc=bar'));

        $tcp->read()->willReturn($encoder->encode($message->toAsn1()));
        $tcp->read(false)->shouldBeCalled()->willReturn(false);

        $this->getMessage()->shouldBeLike($message);
    }

    function it_should_throw_an_exception_on_get_message_when_there_is_none($tcp)
    {
        $tcp->read()->willReturn(false);
        $this->shouldThrow(ConnectionException::class)->duringGetMessage();
    }
}
