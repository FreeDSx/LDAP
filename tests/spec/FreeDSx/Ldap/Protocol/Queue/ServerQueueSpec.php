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
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\MessageWrapperInterface;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Socket\Queue\Buffer;
use FreeDSx\Socket\Socket;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ServerQueueSpec extends ObjectBehavior
{
    public function let(Socket $socket, EncoderInterface $encoder)
    {
        $socket->read(Argument::any())->willReturn('foo', false);
        $encoder->getLastPosition()->willReturn(3);
        $this->beConstructedWith($socket, $encoder);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ServerQueue::class);
    }

    function it_should_send_a_message(Socket $socket, EncoderInterface $encoder)
    {
        $encoder->encode(Argument::any())->shouldBeCalledTimes(1)->willReturn('foo');
        $socket->write(Argument::any())->shouldBeCalledTimes(1);

        $this->sendMessage(new LdapMessageResponse(1, new DeleteResponse(0)));
    }

    function it_should_get_a_request_message(EncoderInterface $encoder, Socket $socket)
    {
        $encoder->decode(Argument::any())->willReturn(Asn1::sequence(
            Asn1::integer(1),
            Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
            new IncompleteType((new LdapEncoder())->encode(Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1()))))
        ));

        $this->getMessage()->shouldBeAnInstanceOf(LdapMessageRequest::class);
    }

    function it_should_send_multiple_messages_with_write_and_respect_the_buffer_size($socket, $encoder)
    {
        $encoder->encode(Argument::any())->shouldBeCalledTimes(2)->willReturn(str_repeat('f', 8000));
        $socket->write(Argument::any())->shouldBeCalledTimes(2);

        $this->sendMessage(
            new LdapMessageResponse(1, new DeleteResponse(0)),
            new LdapMessageResponse(2, new DeleteResponse(0))
        );
    }


    function it_should_set_a_message_wrapper_and_use_it_when_sending_messages(Socket $socket, EncoderInterface $encoder, MessageWrapperInterface $messageWrapper)
    {
        $encoder->encode(Argument::any())->shouldBeCalledTimes(1)->willReturn('foo');
        $socket->write(Argument::any())->shouldBeCalledTimes(1);

        $messageWrapper->wrap('foo')->shouldBeCalled()->willReturn('bar');
        $this->setMessageWrapper($messageWrapper);
        $this->sendMessage(new LdapMessageResponse(1, new DeleteResponse(0)));
    }

    function it_should_set_a_message_wrapper_and_use_it_when_receiving_messages(Socket $socket, EncoderInterface $encoder, MessageWrapperInterface $messageWrapper)
    {
        $asn1 = Asn1::sequence(
            Asn1::integer(1),
            Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
            new IncompleteType((new LdapEncoder())->encode(Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1()))))
        );
        $encoder->decode(Argument::any())->willReturn($asn1);

        $messageWrapper->unwrap('foo')->shouldBeCalled()->willReturn(new Buffer('bar', 3));

        $this->setMessageWrapper($messageWrapper);
        $this->getMessage()->shouldBeAnInstanceOf(LdapMessageRequest::class);
    }
}
