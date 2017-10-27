<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Tcp;

use FreeDSx\Ldap\Asn1\Encoder\BerEncoder;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Tcp\ClientMessageQueue;
use FreeDSx\Ldap\Tcp\TcpClient;
use PhpSpec\ObjectBehavior;

class ClientMessageQueueSpec extends ObjectBehavior
{
    function let(TcpClient $tcp)
    {
        $this->beConstructedWith($tcp, new BerEncoder());
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ClientMessageQueue::class);
    }

    function it_should_return_empty_if_tcp_read_returns_false($tcp)
    {
        $tcp->read()->willReturn(false);

        $this->getMessages()->current()->shouldBeEqualTo(null);
    }

    function it_should_return_a_single_message_on_tcp_read($tcp)
    {
        $encoder = new BerEncoder();
        $message = new LdapMessageResponse(1, new DeleteResponse(0, 'dc=foo,dc=bar', ''));

        $tcp->read()->willReturn($encoder->encode($message->toAsn1()));
        $tcp->read(false)->shouldBeCalled()->willReturn(false);

        $this->getMessage()->shouldBeLike($message);
    }

    function it_should_continue_on_during_partial_PDUs($tcp)
    {
        $encoder = new BerEncoder();
        $message = new LdapMessageResponse(1, new DeleteResponse(0, 'dc=foo,dc=bar', ''));

        $encoded = $encoder->encode($message->toAsn1());
        $part1 = substr($encoded, 0, 10);
        $part2 = substr($encoded, 10);
        $tcp->read()->willReturn($part1, $part2);
        $tcp->read(false)->shouldBeCalled()->willReturn(false);

        $this->getMessage()->shouldBeLike($message);
    }

    /**
     * @todo Need yieldLike and iterateLike matchers. These are currently on phpspec master branch, not released.
     */
    function it_should_get_multiple_messages($tcp)
    {
    }
}
