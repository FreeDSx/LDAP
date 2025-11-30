<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue;

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
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerQueueTest extends TestCase
{
    private ServerQueue $subject;

    private Socket&MockObject $mockSocket;

    private EncoderInterface&MockObject $mockEncoder;

    protected function setUp(): void
    {
        $this->mockSocket = $this->createMock(Socket::class);
        $this->mockEncoder = $this->createMock(EncoderInterface::class);

        $this->mockSocket
            ->method('read')
            ->will(self::onConsecutiveCalls(
                'foo',
                false,
            ));

        $this->mockEncoder
            ->method('getLastPosition')
            ->willReturn(3);

        $this->subject = new ServerQueue(
            $this->mockSocket,
            $this->mockEncoder,
        );
    }

    public function test_it_should_send_a_message(): void
    {
        $this->mockEncoder
            ->method('encode')
            ->willReturn('foo');
        $this->mockSocket
            ->expects($this->once())
            ->method('write');

        $this->subject->sendMessage(new LdapMessageResponse(
            1,
            new DeleteResponse(0)
        ),);
    }

    public function test_it_should_get_a_request_message(): void
    {
        $this->mockEncoder
            ->expects($this->once())
            ->method('decode')
            ->willReturn(
                Asn1::sequence(
                    Asn1::integer(1),
                    Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
                    new IncompleteType((new LdapEncoder())->encode(Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1()))))
                ),
            );

        $this->subject->getMessage();
    }

    public function test_it_should_send_multiple_messages_with_write_and_respect_the_buffer_size(): void
    {
        $this->mockEncoder
            ->expects(self::atLeast(2))
            ->method('encode')
            ->willReturn(str_repeat('f', 8000));

        $this->mockSocket
            ->expects(self::atLeast(2))
            ->method('write');

        $this->subject->sendMessage(
            new LdapMessageResponse(1, new DeleteResponse(0)),
            new LdapMessageResponse(2, new DeleteResponse(0))
        );
    }


    public function test_it_should_set_a_message_wrapper_and_use_it_when_sending_messages(): void
    {
        $this->mockEncoder
            ->method('encode')
            ->willReturn('foo');
        $this->mockSocket
            ->expects($this->once())
            ->method('write');

        $mockWrapper = $this->createMock(MessageWrapperInterface::class);
        $mockWrapper->method('wrap')
            ->with('foo')
            ->willReturn('bar');

        $this->subject->setMessageWrapper($mockWrapper);
        $this->subject->sendMessage(new LdapMessageResponse(
            1,
            new DeleteResponse(0)
        ));
    }

    public function test_it_should_set_a_message_wrapper_and_use_it_when_receiving_messages(): void
    {
        $asn1 = Asn1::sequence(
            Asn1::integer(1),
            Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
            new IncompleteType((new LdapEncoder())->encode(Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1()))))
        );

        $this->mockEncoder
            ->expects($this->once())
            ->method('decode')
            ->willReturn($asn1);

        $mockWrapper = $this->createMock(MessageWrapperInterface::class);
        $mockWrapper
            ->expects($this->once())
            ->method('unwrap')
            ->willReturn(new Buffer('bar', 3));

        $this->subject->setMessageWrapper($mockWrapper);

        $this->subject->getMessage();
    }
}
