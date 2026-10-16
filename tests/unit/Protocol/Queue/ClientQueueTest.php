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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessage;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\Queue\MessageWrapperInterface;
use FreeDSx\Socket\Queue\Buffer;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketPool;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ClientQueueTest extends TestCase
{
    private ClientQueue $subject;

    private SocketPool&MockObject $mockPool;

    private Socket&MockObject $mockSocket;

    private EncoderInterface&MockObject $mockEncoder;

    protected function setUp(): void
    {
        $this->mockPool = $this->createMock(SocketPool::class);
        $this->mockSocket = $this->createMock(Socket::class);
        $this->mockEncoder = $this->createMock(EncoderInterface::class);

        $this->mockEncoder
            ->method('getLastPosition')
            ->willReturn(3);

        $this->mockPool
            ->method('connect')
            ->willReturn($this->mockSocket);

        $this->mockSocket
            ->method('read')
            ->willReturnOnConsecutiveCalls(
                'foo',
                false,
            );

        $this->subject = new ClientQueue(
            $this->mockPool,
            $this->mockEncoder,
        );
    }

    public function test_it_should_send_a_message(): void
    {
        $this->mockEncoder
            ->expects($this->once())
            ->method('encode')
            ->willReturn('foo');

        $this->mockSocket
            ->expects($this->once())
            ->method('write')
            ->with('foo');

        $this->subject->sendMessage(new LdapMessageRequest(
            1,
            Operations::whoami(),
        ));
    }

    public function test_it_should_get_a_response_message(): void
    {
        $this->mockEncoder
            ->expects($this->once())
            ->method('decode')
            ->willReturn(
                Asn1::sequence(
                    Asn1::integer(3),
                    Asn1::application(11, Asn1::sequence(
                        Asn1::enumerated(0),
                        Asn1::octetString('dc=foo,dc=bar'),
                        Asn1::octetString(''),
                    )),
                    Asn1::context(0, (new IncompleteType((new LdapEncoder())->encode((new Control('foo'))->toAsn1())))->setIsConstructed(true)),
                ),
            );

        $this->subject->getMessage();
    }

    public function test_it_should_throw_an_unsolicited_notification_exception_when_one_is_received(): void
    {
        $this->mockEncoder
            ->method('decode')
            ->willReturn(
                Asn1::sequence(
                    Asn1::integer(0),
                    Asn1::application(24, Asn1::sequence(
                        Asn1::enumerated(0),
                        Asn1::octetString('dc=foo,dc=bar'),
                        Asn1::octetString('foo'),
                        Asn1::context(10, Asn1::octetString(ExtendedResponse::OID_NOTICE_OF_DISCONNECTION)),
                    )),
                ),
            );

        self::expectException(UnsolicitedNotificationException::class);

        $this->subject->getMessage();
    }

    public function test_it_should_throw_a_protocol_exception_if_the_message_id_was_unexpected(): void
    {
        $this->mockEncoder
            ->method('decode')
            ->willReturn(
                Asn1::sequence(
                    Asn1::integer(3),
                    Asn1::application(11, Asn1::sequence(
                        Asn1::enumerated(0),
                        Asn1::octetString('dc=foo,dc=bar'),
                        Asn1::octetString(''),
                    )),
                    Asn1::context(0, (new IncompleteType((new LdapEncoder())->encode((new Control('foo'))->toAsn1())))->setIsConstructed(true)),
                ),
            );

        self::expectException(ProtocolException::class);

        $this->subject->getMessage(2);
    }

    public function test_it_should_set_a_message_wrapper_and_use_it_when_sending_messages(): void
    {
        $mockWrapper = $this->createMock(MessageWrapperInterface::class);

        $this->mockEncoder
            ->method('encode')
            ->willReturn('foo');
        $this->mockSocket
            ->expects($this->once())
            ->method('write');

        $mockWrapper
            ->expects($this->atLeastOnce())
            ->method('wrap')
            ->with('foo')
            ->willReturn('bar');

        $this->subject->setMessageWrapper($mockWrapper);
        $this->subject->sendMessage(new LdapMessageRequest(
            1,
            Operations::whoami(),
        ));
    }

    public function test_it_should_set_a_message_wrapper_and_use_it_when_receiving_messages(): void
    {
        $asn1 = Asn1::sequence(
            Asn1::integer(3),
            Asn1::application(11, Asn1::sequence(
                Asn1::enumerated(0),
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::octetString(''),
            )),
            Asn1::context(0, (new IncompleteType((new LdapEncoder())->encode((new Control('foo'))->toAsn1())))->setIsConstructed(true)),
        );

        $this->mockEncoder
            ->method('decode')
            ->with('bar')
            ->willReturn($asn1);

        $mockWrapper = $this->createMock(MessageWrapperInterface::class);
        $mockWrapper
            ->expects($this->once())
            ->method('unwrap')
            ->with('foo')
            ->willReturn(new Buffer('bar', 3));

        $this->subject->setMessageWrapper($mockWrapper);

        $this->subject->getMessage();
    }

    public function test_it_should_decode_a_search_result_entry_identically_to_the_type_graph(): void
    {
        $bytes = $this->encodeSearchResultEntry(7);

        self::assertEquals(
            LdapMessageResponse::fromAsn1((new LdapEncoder())->decode($bytes)),
            $this->queueReceiving($bytes)->getMessage(),
        );
    }

    public function test_it_should_decode_a_search_result_entry_with_controls_identically_to_the_type_graph(): void
    {
        $bytes = $this->encodeSearchResultEntry(
            7,
            new Control('1.2.3'),
        );

        self::assertEquals(
            LdapMessageResponse::fromAsn1((new LdapEncoder())->decode($bytes)),
            $this->queueReceiving($bytes)->getMessage(),
        );
    }

    public function test_it_should_decode_a_search_result_entry_received_across_reads(): void
    {
        $bytes = $this->encodeSearchResultEntry(7);
        $half = intdiv(
            strlen($bytes),
            2,
        );

        self::assertEquals(
            LdapMessageResponse::fromAsn1((new LdapEncoder())->decode($bytes)),
            $this->queueReceiving(
                substr(
                    $bytes,
                    0,
                    $half,
                ),
                substr(
                    $bytes,
                    $half,
                ),
            )->getMessage(),
        );
    }

    public function test_it_should_decode_consecutive_search_result_entries_from_a_single_read(): void
    {
        $first = $this->encodeSearchResultEntry(1);
        $second = $this->encodeSearchResultEntry(2);
        $queue = $this->queueReceiving($first . $second);

        self::assertSame(
            1,
            $queue->getMessage()->getMessageId(),
        );
        self::assertSame(
            2,
            $queue->getMessage()->getMessageId(),
        );
    }

    public function test_it_should_decode_a_search_result_entry_only_the_type_graph_tolerates(): void
    {
        $bytes = (new LdapEncoder())->encode(Asn1::sequence(
            Asn1::integer(3),
            Asn1::application(SearchResultEntry::TAG_NUMBER, Asn1::sequence(
                Asn1::octetString('cn=foo,dc=bar'),
                Asn1::sequenceOf(Asn1::sequence(
                    Asn1::octetString('cn'),
                    Asn1::sequence(Asn1::octetString('foo')),
                )),
            )),
        ));

        self::assertEquals(
            LdapMessageResponse::fromAsn1((new LdapEncoder())->decode($bytes)),
            $this->queueReceiving($bytes)->getMessage(),
        );
    }

    public function test_it_should_reject_a_malformed_search_result_entry_as_the_type_graph_does(): void
    {
        $bytes = (new LdapEncoder())->encode(Asn1::sequence(
            Asn1::integer(3),
            Asn1::application(SearchResultEntry::TAG_NUMBER, Asn1::sequence(
                Asn1::octetString('cn=foo,dc=bar'),
                Asn1::sequenceOf(Asn1::sequence(
                    Asn1::octetString('cn'),
                    Asn1::setOf(Asn1::integer(1)),
                )),
            )),
        ));

        $this->expectException(MessageDecodeException::class);
        $this->expectExceptionMessage('The search result entry is malformed.');

        $this->queueReceiving($bytes)->getMessage();
    }

    public function test_it_should_reject_a_search_result_entry_with_an_out_of_range_message_id(): void
    {
        $bytes = (new LdapEncoder())->encode(Asn1::sequence(
            Asn1::integer(LdapMessage::MAX_INT + 1),
            Asn1::application(SearchResultEntry::TAG_NUMBER, Asn1::sequence(
                Asn1::octetString('cn=foo,dc=bar'),
                Asn1::sequenceOf(),
            )),
        ));

        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The LDAP message ID is outside the range it is permitted to use.');

        $this->queueReceiving($bytes)->getMessage();
    }

    private function encodeSearchResultEntry(
        int $messageId,
        Control ...$controls,
    ): string {
        $entry = Entry::fromArray(
            'cn=foo,dc=bar',
            [
                'cn' => ['foo'],
                'objectClass' => ['top', 'person'],
                'description' => [
                    str_repeat(
                        'd',
                        200,
                    ),
                ],
            ],
        );

        return (new LdapEncoder())->encode((new LdapMessageResponse(
            $messageId,
            new SearchResultEntry($entry),
            ...$controls,
        ))->toAsn1());
    }

    private function queueReceiving(string ...$reads): ClientQueue
    {
        $responses = array_values($reads);
        $responses[] = false;

        $socket = $this->createMock(Socket::class);
        $socket
            ->method('read')
            ->willReturnOnConsecutiveCalls(...$responses);

        $pool = $this->createMock(SocketPool::class);
        $pool
            ->method('connect')
            ->willReturn($socket);

        return new ClientQueue($pool);
    }
}
