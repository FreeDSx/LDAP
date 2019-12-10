<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\Queue;

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
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\Queue\MessageWrapperInterface;
use FreeDSx\Socket\Queue\Buffer;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketPool;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientQueueSpec extends ObjectBehavior
{
    public function let(SocketPool $socketPool, Socket $socket, EncoderInterface $encoder)
    {
        $socket->read(Argument::any())->willReturn('foo', false);
        $encoder->getLastPosition()->willReturn(3);
        $socketPool->connect(Argument::any())->shouldBeCalled()->willReturn($socket);

        $this->beConstructedWith($socketPool, $encoder);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ClientQueue::class);
    }

    function it_should_send_a_message(Socket $socket, EncoderInterface $encoder)
    {
        $encoder->encode(Argument::any())->shouldBeCalledTimes(1)->willReturn('foo');
        $socket->write(Argument::any())->shouldBeCalledTimes(1);

        $this->sendMessage(new LdapMessageRequest(1, Operations::whoami()));
    }

    function it_should_get_a_response_message(EncoderInterface $encoder)
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

    function it_should_throw_an_unsolicited_notification_exception_when_one_is_received(EncoderInterface $encoder, Socket $socket)
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

    function it_should_throw_a_protocol_exception_if_the_message_id_was_unexpected(EncoderInterface $encoder)
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


    function it_should_set_a_message_wrapper_and_use_it_when_sending_messages(Socket $socket, EncoderInterface $encoder, MessageWrapperInterface $messageWrapper)
    {
        $encoder->encode(Argument::any())->shouldBeCalledTimes(1)->willReturn('foo');
        $socket->write(Argument::any())->shouldBeCalledTimes(1);

        $messageWrapper->wrap('foo')->shouldBeCalled()->willReturn('bar');
        $this->setMessageWrapper($messageWrapper);
        $this->sendMessage(new LdapMessageRequest(1, Operations::whoami()));
    }

    function it_should_set_a_message_wrapper_and_use_it_when_receiving_messages(Socket $socket, EncoderInterface $encoder, MessageWrapperInterface $messageWrapper)
    {
        $asn1 = Asn1::sequence(
            Asn1::integer(3),
            Asn1::application(11, Asn1::sequence(
                Asn1::integer(0),
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::octetString('')
            )),
            Asn1::context(0, (new IncompleteType((new LdapEncoder())->encode((new Control('foo'))->toAsn1())))->setIsConstructed(true))
        );
        $encoder->decode('bar')->willReturn($asn1);
        $messageWrapper->unwrap('foo')->shouldBeCalled()->willReturn(new Buffer('bar', 3));

        $this->setMessageWrapper($messageWrapper);
        $this->getMessage()->shouldBeAnInstanceOf(LdapMessageResponse::class);
    }
}
