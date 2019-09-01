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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Encoder\EncoderInterface;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\LdapQueue;
use FreeDSx\Socket\Queue\Asn1MessageQueue;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketPool;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapQueueSpec extends ObjectBehavior
{
    function let(SocketPool $socketPool, Socket $socket, EncoderInterface $encoder)
    {
        $socketPool->connect(Argument::any())->willReturn($socket);
        $socket->read(Argument::any())->willReturn('foo', false);
        $encoder->getLastPosition()->willReturn(3);

        $this->beConstructedThrough('usingSocketPool', [$socketPool, $encoder]);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LdapQueue::class);
    }

    function it_should_be_constructable_with_a_socket_only(Socket $socket, EncoderInterface $encoder)
    {
        $this->beConstructedWith($socket, $encoder);

        $this->shouldHaveType(LdapQueue::class);
    }

    function it_should_extend_the_Asn1MessageQueue()
    {
        $this->shouldBeAnInstanceOf(Asn1MessageQueue::class);
    }

    function it_should_send_a_message($socket, $encoder)
    {
        $encoder->encode(Argument::any())->shouldBeCalledTimes(1)->willReturn('foo');
        $socket->write(Argument::any())->shouldBeCalledTimes(1);

        $this->sendMessage(new LdapMessageRequest(1, Operations::whoami()));
    }

    function it_should_send_multiple_messages_with_one_write_when_under_the_buffer_size($socket, $encoder)
    {
        $encoder->encode(Argument::any())->shouldBeCalledTimes(2)->willReturn(str_repeat('f', 2000));
        $socket->write(Argument::any())->shouldBeCalledTimes(1);

        $this->sendMessage(
            new LdapMessageRequest(1, Operations::whoami()),
            new LdapMessageRequest(1, Operations::whoami())
        );
    }

    function it_should_send_multiple_messages_with_write_and_respect_the_buffer_size($socket, $encoder)
    {
        $encoder->encode(Argument::any())->shouldBeCalledTimes(2)->willReturn(str_repeat('f', 8000));
        $socket->write(Argument::any())->shouldBeCalledTimes(2);

        $this->sendMessage(
            new LdapMessageRequest(1, Operations::whoami()),
            new LdapMessageRequest(1, Operations::whoami())
        );
    }

    function it_should_get_a_requst_message($encoder, $socket)
    {
        $this->beConstructedWith($socket, $encoder, true);

        $encoder->decode(Argument::any())->willReturn(Asn1::sequence(
            Asn1::integer(1),
            Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
            new IncompleteType((new LdapEncoder())->encode(Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1()))))
        ));
        $this->getMessage()->shouldBeAnInstanceOf(LdapMessageRequest::class);
    }

    function it_should_get_a_response_message($encoder, $socket)
    {
        $encoder->decode(Argument::any())->willReturn(Asn1::sequence(
            Asn1::integer(3),
            Asn1::application(11, Asn1::sequence(
                Asn1::integer(0),
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::octetString('')
            )),
            Asn1::context(0, (new IncompleteType((new LdapEncoder())->encode((new Control('foo'))->toAsn1())))->setIsConstructed(true))
        ));

        $this->getMessage()->shouldBeAnInstanceOf(LdapMessageResponse::class);
    }

    function it_should_get_the_current_id()
    {
        $this->currentId()->shouldBeEqualTo(0);
    }

    function it_should_generate_an_id()
    {
        $this->generateId()->shouldBeEqualTo(1);
        $this->generateId()->shouldBeEqualTo(2);
    }

    function it_should_throw_an_unsolicited_notification_exception_when_one_is_received($encoder, $socket)
    {
        $encoder->decode(Argument::any())->willReturn(Asn1::sequence(
            Asn1::integer(0),
            Asn1::application(24,Asn1::sequence(
                Asn1::enumerated(0),
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::octetString('foo'),
                Asn1::context(10, Asn1::octetString(ExtendedResponse::OID_NOTICE_OF_DISCONNECTION))
        ))));

        $this->shouldThrow(UnsolicitedNotificationException::class)->during('getMessage');
    }

    function it_should_throw_a_protocol_exception_if_the_message_id_was_unexpected($encoder, $socket)
    {
        $encoder->decode(Argument::any())->willReturn(Asn1::sequence(
            Asn1::integer(3),
            Asn1::application(11, Asn1::sequence(
                Asn1::integer(0),
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::octetString('')
            )),
            Asn1::context(0, (new IncompleteType((new LdapEncoder())->encode((new Control('foo'))->toAsn1())))->setIsConstructed(true))
        ));

        $this->shouldThrow(ProtocolException::class)->during('getMessage', [2]);
    }
}
