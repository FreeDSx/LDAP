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
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Exception\RequestSizeExceededException;
use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Protocol\Queue\MessageWrapperInterface;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Socket\Queue\Buffer;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Protocol\Queue\Response\RecordingInterceptor;

final class ServerQueueTest extends TestCase
{
    /**
     * Comfortably past the buffer cap, so an uncapped peek would read on every attempt.
     */
    private const FLOOD_ATTEMPTS = 500;

    private ServerQueue $subject;

    private Socket&MockObject $mockSocket;

    private EncoderInterface&MockObject $mockEncoder;

    protected function setUp(): void
    {
        $this->mockSocket = $this->createMock(Socket::class);
        $this->mockEncoder = $this->createMock(EncoderInterface::class);

        $this->mockSocket
            ->method('read')
            ->willReturnOnConsecutiveCalls(
                'foo',
                false,
            );

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
            new DeleteResponse(0),
        ), );
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
                    new IncompleteType((new LdapEncoder())->encode(Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1())))),
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
            new LdapMessageResponse(2, new DeleteResponse(0)),
        );
    }

    public function test_it_records_bytes_sent_for_each_outgoing_message(): void
    {
        $recorder = new InMemoryMetricsRecorder();
        $encoder = $this->createMock(EncoderInterface::class);
        $encoder->method('encode')->willReturn('abcdef');
        $socket = $this->createMock(Socket::class);

        $queue = new ServerQueue(
            $socket,
            $encoder,
            metricsRecorder: $recorder,
        );
        $queue->sendMessage(new LdapMessageResponse(
            1,
            new DeleteResponse(0),
        ));

        self::assertSame(
            6,
            $recorder->snapshot()->traffic->bytesSent,
        );
    }

    public function test_it_records_bytes_received_for_each_decoded_request(): void
    {
        $recorder = new InMemoryMetricsRecorder();
        $encoder = $this->createMock(EncoderInterface::class);
        $encoder->method('getLastPosition')->willReturn(42);
        $encoder->expects($this->once())
            ->method('decode')
            ->willReturn(Asn1::sequence(
                Asn1::integer(1),
                Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
                new IncompleteType((new LdapEncoder())->encode(Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1())))),
            ));
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturnOnConsecutiveCalls(
            'foo',
            false,
        );

        $queue = new ServerQueue(
            $socket,
            $encoder,
            metricsRecorder: $recorder,
        );
        $queue->getMessage();

        self::assertSame(
            42,
            $recorder->snapshot()->traffic->bytesReceived,
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
            new DeleteResponse(0),
        ));
    }

    public function test_it_should_set_a_message_wrapper_and_use_it_when_receiving_messages(): void
    {
        $asn1 = Asn1::sequence(
            Asn1::integer(1),
            Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
            new IncompleteType((new LdapEncoder())->encode(Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1())))),
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

    public function test_peek_returns_null_when_no_socket_data(): void
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn(false);

        $queue = new ServerQueue($socket, new LdapEncoder());

        self::assertNull($queue->peekForCancelSignal(2));
    }

    public function test_peek_returns_abandon_request_targeting_in_flight_message(): void
    {
        $queue = $this->makeQueueWithEncodedRequest(
            new LdapMessageRequest(3, new AbandonRequest(2)),
        );

        $result = $queue->peekForCancelSignal(2);

        self::assertNotNull($result);
        self::assertInstanceOf(
            AbandonRequest::class,
            $result->getRequest(),
        );
    }

    public function test_peek_returns_cancel_request_targeting_in_flight_message(): void
    {
        $queue = $this->makeQueueWithEncodedRequest(
            new LdapMessageRequest(3, new CancelRequest(2)),
        );

        $result = $queue->peekForCancelSignal(2);

        self::assertNotNull($result);
        self::assertInstanceOf(
            CancelRequest::class,
            $result->getRequest(),
        );
    }

    public function test_peek_buffers_non_cancel_message_and_returns_null(): void
    {
        $queue = $this->makeQueueWithEncodedRequest(
            new LdapMessageRequest(5, new DeleteRequest('dc=foo,dc=bar')),
        );

        self::assertNull($queue->peekForCancelSignal(2));

        $buffered = $queue->getMessage();

        self::assertSame(
            5,
            $buffered->getMessageId(),
        );
        self::assertInstanceOf(
            DeleteRequest::class,
            $buffered->getRequest(),
        );
    }

    public function test_peek_refuses_a_cancel_carrying_a_zero_message_id(): void
    {
        $queue = $this->makeQueueWithEncodedRequest(
            new LdapMessageRequest(0, new CancelRequest(2)),
        );

        self::expectException(RequestValidationException::class);
        self::expectExceptionMessage('The message ID 0 cannot be used in a client request.');

        $queue->peekForCancelSignal(2);
    }

    public function test_peek_refuses_an_unrelated_message_carrying_a_zero_message_id(): void
    {
        $queue = $this->makeQueueWithEncodedRequest(
            new LdapMessageRequest(0, new DeleteRequest('dc=foo,dc=bar')),
        );

        self::expectException(RequestValidationException::class);

        $queue->peekForCancelSignal(2);
    }

    public function test_peek_finds_a_cancel_queued_behind_an_unrelated_message(): void
    {
        $encoder = new LdapEncoder();
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn(
            $encoder->encode((new LdapMessageRequest(5, new DeleteRequest('dc=foo,dc=bar')))->toAsn1())
                . $encoder->encode((new LdapMessageRequest(6, new CancelRequest(2)))->toAsn1()),
            false,
        );

        $queue = new ServerQueue($socket, $encoder);

        $buffered = $queue->peekForCancelSignal(2);
        $signal = $queue->peekForCancelSignal(2);

        self::assertNull($buffered);
        self::assertInstanceOf(
            CancelRequest::class,
            $signal?->getRequest(),
        );
    }

    public function test_peek_stops_reading_once_the_pending_buffer_is_full(): void
    {
        $encoder = new LdapEncoder();
        $bytes = $encoder->encode(
            (new LdapMessageRequest(5, new DeleteRequest('dc=foo,dc=bar')))->toAsn1(),
        );
        $reads = 0;

        $socket = $this->createMock(Socket::class);
        $socket->method('read')
            ->willReturnCallback(function () use ($bytes, &$reads): string {
                $reads++;

                return $bytes;
            });

        $queue = new ServerQueue($socket, $encoder);

        for ($attempt = 0; $attempt < self::FLOOD_ATTEMPTS; $attempt++) {
            self::assertNull($queue->peekForCancelSignal(2));
        }

        self::assertLessThan(
            self::FLOOD_ATTEMPTS,
            $reads,
        );
    }

    public function test_peek_buffers_abandon_targeting_different_message_and_returns_null(): void
    {
        $queue = $this->makeQueueWithEncodedRequest(
            new LdapMessageRequest(3, new AbandonRequest(99)),
        );

        self::assertNull($queue->peekForCancelSignal(2));

        $buffered = $queue->getMessage();

        self::assertInstanceOf(
            AbandonRequest::class,
            $buffered->getRequest(),
        );
    }

    public function test_get_message_drains_pending_before_reading_socket(): void
    {
        $encoder = new LdapEncoder();
        $bytes = $encoder->encode(
            (new LdapMessageRequest(5, new DeleteRequest('dc=foo,dc=bar')))->toAsn1(),
        );

        $socket = $this->createMock(Socket::class);
        $socket->expects(self::once())
            ->method('read')
            ->willReturn($bytes);

        $queue = new ServerQueue($socket, $encoder);

        // Peek decodes and buffers the DeleteRequest into pendingMessages
        $queue->peekForCancelSignal(2);

        // getMessage() must drain pendingMessages — no second socket read
        $result = $queue->getMessage();

        self::assertInstanceOf(
            DeleteRequest::class,
            $result->getRequest(),
        );
    }

    public function test_it_should_reject_a_request_whose_declared_length_exceeds_the_max_receive_size(): void
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn(hex2bin('3084000000c8'));

        $queue = new ServerQueue($socket, maxReceiveSize: 100);

        $this->expectException(RequestSizeExceededException::class);

        $queue->getMessage();
    }

    public function test_it_should_decode_a_request_within_the_max_receive_size(): void
    {
        $encoder = new LdapEncoder();
        $bytes = $encoder->encode(
            (new LdapMessageRequest(5, new DeleteRequest('dc=foo,dc=bar')))->toAsn1(),
        );

        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn($bytes);

        $queue = new ServerQueue($socket, maxReceiveSize: 5_242_880);

        self::assertSame(
            5,
            $queue->getMessage()->getMessageId(),
        );
    }

    public function test_it_applies_interceptors_to_a_sent_message(): void
    {
        $this->mockEncoder
            ->method('encode')
            ->willReturn('foo');
        $this->mockSocket
            ->expects($this->once())
            ->method('write');

        $queue = new ServerQueue(
            $this->mockSocket,
            $this->mockEncoder,
            interceptors: [new RecordingInterceptor(new CallLog(), '1.2.3.4')],
        );

        $message = new LdapMessageResponse(
            1,
            new DeleteResponse(0),
        );
        $queue->sendMessage($message);

        self::assertTrue($message->controls()->has('1.2.3.4'));
    }

    public function test_it_applies_interceptors_to_each_streamed_message(): void
    {
        $this->mockEncoder
            ->method('encode')
            ->willReturn('foo');

        $queue = new ServerQueue(
            $this->mockSocket,
            $this->mockEncoder,
            interceptors: [new RecordingInterceptor(new CallLog(), '1.2.3.4')],
        );

        $messages = [
            new LdapMessageResponse(1, new DeleteResponse(0)),
            new LdapMessageResponse(2, new DeleteResponse(0)),
        ];
        $queue->sendMessages($messages);

        foreach ($messages as $message) {
            self::assertTrue($message->controls()->has('1.2.3.4'));
        }
    }

    public function test_it_runs_interceptors_in_order(): void
    {
        $this->mockEncoder
            ->method('encode')
            ->willReturn('foo');

        $log = new CallLog();
        $queue = new ServerQueue(
            $this->mockSocket,
            $this->mockEncoder,
            interceptors: [
                new RecordingInterceptor($log, 'a'),
                new RecordingInterceptor($log, 'b'),
            ],
        );

        $queue->sendMessage(new LdapMessageResponse(
            1,
            new DeleteResponse(0),
        ));

        self::assertSame(
            ['a', 'b'],
            $log->entries,
        );
    }

    public function test_it_encodes_a_search_result_entry_identically_to_the_generic_path(): void
    {
        $message = new LdapMessageResponse(
            2,
            new SearchResultEntry(new Entry(
                'cn=foo,dc=example,dc=com',
                new Attribute('cn', 'foo'),
                new Attribute('objectClass', 'top', 'person'),
                new Attribute('sn', 'Foo'),
                new Attribute('userCertificate;binary', "\x00\x01\x02"),
                new Attribute('emptyAttribute'),
            )),
        );

        self::assertSame(
            (new LdapEncoder())->encode($message->toAsn1()),
            $this->captureSentBytes($message),
        );
    }

    public function test_it_encodes_a_search_result_entry_with_controls_identically(): void
    {
        $message = new LdapMessageResponse(
            3,
            new SearchResultEntry(new Entry(
                'cn=bar,dc=example,dc=com',
                new Attribute('cn', 'bar'),
            )),
            new Control('1.2.3.4'),
        );

        self::assertSame(
            (new LdapEncoder())->encode($message->toAsn1()),
            $this->captureSentBytes($message),
        );
    }

    public function test_it_encodes_a_sync_entry_with_a_state_control_identically(): void
    {
        $message = new LdapMessageResponse(
            4,
            new SearchResultEntry(new Entry(
                'cn=synced,dc=example,dc=com',
                new Attribute('cn', 'synced'),
                new Attribute('objectClass', 'top', 'person'),
            )),
            new SyncStateControl(
                SyncStateControl::STATE_ADD,
                str_repeat("\x11", 16),
            ),
        );

        self::assertSame(
            (new LdapEncoder())->encode($message->toAsn1()),
            $this->captureSentBytes($message),
        );
    }

    /**
     * Sends the message through a real-encoder queue and returns the bytes written to the socket.
     */
    private function captureSentBytes(LdapMessageResponse $message): string
    {
        $written = '';
        $socket = $this->createMock(Socket::class);
        $socket->method('write')->willReturnCallback(function (string $data) use (&$written, $socket): Socket {
            $written .= $data;

            return $socket;
        });

        # A null encoder builds a real LdapEncoder, so the real search-entry fast path runs.
        (new ServerQueue($socket))->sendMessage($message);

        return $written;
    }

    private function makeQueueWithEncodedRequest(LdapMessageRequest $message): ServerQueue
    {
        $encoder = new LdapEncoder();
        $bytes = $encoder->encode($message->toAsn1());

        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn($bytes);

        return new ServerQueue($socket, $encoder);
    }
}
