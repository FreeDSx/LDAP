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

use Closure;
use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\PduDepthException;
use FreeDSx\Asn1\Exception\PduElementsException;
use FreeDSx\Asn1\Exception\PduLengthException;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RequestSizeExceededException;
use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Protocol\Queue\RequestLimits;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Exception\ReadTimeoutException;
use FreeDSx\Socket\Exception\WriteTimeoutException;
use FreeDSx\Socket\Socket;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Protocol\Queue\Response\RecordingInterceptor;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Throwable;

final class ServerQueueTest extends TestCase
{
    use ServerContainerTrait;

    /**
     * Comfortably past the buffer cap, so an uncapped peek would read on every attempt.
     */
    private const FLOOD_ATTEMPTS = 500;

    private ServerQueue $subject;

    private Socket&MockObject $mockSocket;

    private LdapEncoder&MockObject $mockEncoder;

    private RequestMessageDecoder $messageDecoder;

    private ServerAuthorization $authorization;

    private RequestLimits $limits;

    protected function setUp(): void
    {
        $this->mockSocket = $this->createMock(Socket::class);
        $this->mockEncoder = $this->createMock(LdapEncoder::class);
        $this->messageDecoder = $this->fromContainer(RequestMessageDecoder::class);
        $this->authorization = new ServerAuthorization(TestServerOptions::defaults());
        $this->limits = new RequestLimits($this->authorization);

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
            $this->messageDecoder,
            $this->limits,
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

    public function test_a_stream_started_while_another_write_holds_the_connection_is_refused_without_writing(): void
    {
        $refused = null;
        $this->mockEncoder
            ->method('encode')
            ->willReturn('foo');
        $this->mockSocket
            ->expects(self::once())
            ->method('write')
            ->willReturnCallback(function () use (&$refused): Socket {
                try {
                    $this->subject->sendMessages([new LdapMessageResponse(
                        2,
                        new DeleteResponse(0),
                    )]);
                } catch (ConnectionException $e) {
                    $refused = $e;
                }

                return $this->mockSocket;
            });

        $this->subject->sendMessage(new LdapMessageResponse(
            1,
            new DeleteResponse(0),
        ));

        self::assertInstanceOf(
            ConnectionException::class,
            $refused,
        );
    }

    public function test_a_queue_whose_writes_went_out_has_no_failed_write(): void
    {
        $this->mockEncoder
            ->method('encode')
            ->willReturn('foo');

        $this->subject->sendMessage(new LdapMessageResponse(
            1,
            new DeleteResponse(0),
        ));

        self::assertFalse($this->subject->hasFailedWrite());
    }

    public function test_a_write_the_socket_did_not_finish_leaves_a_failed_write(): void
    {
        $this->failWrite();

        self::assertTrue($this->subject->hasFailedWrite());
    }

    public function test_a_send_after_a_failed_write_fails_the_same_way_without_writing(): void
    {
        $failure = $this->failWrite();

        $this->expectExceptionObject($failure);

        $this->subject->sendMessage(new LdapMessageResponse(
            2,
            new DeleteResponse(0),
        ));
    }

    public function test_a_failed_write_is_rethrown_when_asked(): void
    {
        $failure = $this->failWrite();

        $this->expectExceptionObject($failure);

        $this->subject->throwIfWriteFailed();
    }

    public function test_nothing_is_thrown_when_asked_and_no_write_failed(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->throwIfWriteFailed();
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

    public function test_a_response_sent_while_another_is_going_out_is_not_written_into_the_middle_of_it(): void
    {
        $this->mockEncoder
            ->method('encode')
            ->willReturn(str_repeat('f', 8000));

        $log = new CallLog();

        $this->mockSocket
            ->method('write')
            ->willReturnCallback(function () use ($log) {
                $log->record('start');

                // Stands in for the signal handler, which sends from inside the write it interrupted.
                if (count($log->entries) === 1) {
                    $this->subject->sendMessage(new LdapMessageResponse(
                        0,
                        new DeleteResponse(0),
                    ));
                }

                $log->record('end');

                return $this->mockSocket;
            });

        $this->subject->sendMessage(
            new LdapMessageResponse(1, new DeleteResponse(0)),
            new LdapMessageResponse(2, new DeleteResponse(0)),
        );

        $alternating = [];

        foreach (array_keys($log->entries) as $index) {
            $alternating[] = $index % 2 === 0
                ? 'start'
                : 'end';
        }

        self::assertSame(
            $alternating,
            $log->entries,
            'A response was written while another was still going out.',
        );
    }

    public function test_a_close_while_a_response_is_going_out_waits_until_it_has_been_written(): void
    {
        $this->mockEncoder
            ->method('encode')
            ->willReturn(str_repeat('f', 8000));

        $log = new CallLog();

        $this->mockSocket
            ->method('write')
            ->willReturnCallback(function () use ($log) {
                $log->record('write');

                if (count($log->entries) === 1) {
                    $this->subject->close();
                }

                return $this->mockSocket;
            });
        $this->mockSocket
            ->method('close')
            ->willReturnCallback(function () use ($log) {
                $log->record('close');

                return $this->mockSocket;
            });

        $this->subject->sendMessage(
            new LdapMessageResponse(1, new DeleteResponse(0)),
            new LdapMessageResponse(2, new DeleteResponse(0)),
        );

        self::assertSame(
            'close',
            end($log->entries),
            'The socket was closed while a response was still going out.',
        );
        self::assertCount(
            1,
            array_keys($log->entries, 'close', true),
        );
    }

    public function test_a_close_while_streaming_stops_the_responses_that_have_not_been_sent(): void
    {
        $this->mockEncoder
            ->method('encode')
            ->willReturn(str_repeat('f', 8000));

        $log = new CallLog();
        $responses = (function () use ($log): Generator {
            foreach (range(1, 20) as $id) {
                $log->record("entry-{$id}");

                yield new LdapMessageResponse(
                    $id,
                    new DeleteResponse(0),
                );
            }
        })();

        $this->mockSocket
            ->method('write')
            ->willReturnCallback(function () {
                $this->subject->close();

                return $this->mockSocket;
            });

        $this->subject->sendMessages($responses);

        self::assertLessThan(
            20,
            count($log->entries),
            'The whole result set was produced even though the session was ending.',
        );
    }

    public function test_it_records_bytes_sent_for_each_outgoing_message(): void
    {
        $recorder = new InMemoryMetricsRecorder();
        $encoder = $this->createMock(LdapEncoder::class);
        $encoder->method('encode')->willReturn('abcdef');
        $socket = $this->createMock(Socket::class);

        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            $this->limits,
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
        $encoder = $this->createMock(LdapEncoder::class);
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
            $this->messageDecoder,
            $this->limits,
            $encoder,
            metricsRecorder: $recorder,
        );
        $queue->getMessage();

        self::assertSame(
            42,
            $recorder->snapshot()->traffic->bytesReceived,
        );
    }

    public function test_a_client_between_requests_is_waited_on_under_the_idle_timeout_alone(): void
    {
        $timeouts = [];
        $queue = $this->queueReading(
            [self::encodedDelete(1)],
            $timeouts,
        );

        $queue->getMessage();

        self::assertSame(
            [null],
            $timeouts,
        );
    }

    public function test_the_rest_of_a_request_is_waited_on_for_no_longer_than_the_read_timeout(): void
    {
        $timeouts = [];
        $queue = $this->queueReading(
            self::chunksOf(
                self::encodedDelete(1),
                5,
                5,
            ),
            $timeouts,
        );

        $queue->getMessage();

        self::assertGreaterThan(
            29.9,
            $timeouts[1],
        );
        self::assertLessThanOrEqual(
            30.0,
            $timeouts[1],
        );
        self::assertLessThanOrEqual(
            $timeouts[1],
            $timeouts[2],
        );
    }

    public function test_each_request_has_the_whole_read_timeout_to_arrive(): void
    {
        $first = self::encodedDelete(1);
        $timeouts = [];
        $queue = $this->queueReading(
            self::chunksOf(
                $first . self::encodedDelete(2),
                5,
                strlen($first),
            ),
            $timeouts,
        );

        $queue->getMessage();
        usleep(50_000);
        $queue->getMessage();

        self::assertGreaterThan(
            29.99,
            $timeouts[2],
        );
    }

    public function test_a_read_timeout_of_zero_leaves_every_wait_to_the_idle_timeout(): void
    {
        $timeouts = [];
        $queue = $this->queueReading(
            self::chunksOf(
                self::encodedDelete(1),
                5,
            ),
            $timeouts,
            readTimeout: 0,
        );

        $queue->getMessage();

        self::assertSame(
            [null, null],
            $timeouts,
        );
    }

    public function test_a_request_read_ahead_during_a_response_is_waited_on_for_no_longer_than_the_read_timeout(): void
    {
        $timeouts = [];
        $queue = $this->queueReading(
            self::chunksOf(
                self::encodedDelete(3),
                5,
            ),
            $timeouts,
        );

        $queue->peekForCancelSignal(2);

        self::assertGreaterThan(
            29.9,
            $timeouts[1],
        );
        self::assertLessThanOrEqual(
            30.0,
            $timeouts[1],
        );
    }

    public function test_a_request_that_does_not_arrive_in_time_names_the_read_timeout(): void
    {
        $timeouts = [];
        $queue = $this->queueReading(
            [
                self::chunksOf(
                    self::encodedDelete(1),
                    5,
                )[0],
                new ReadTimeoutException('The read did not complete within its timeout of 0 seconds.'),
            ],
            $timeouts,
        );

        $this->expectException(ReadTimeoutException::class);
        $this->expectExceptionMessage('The request did not finish arriving within 30 seconds.');

        $queue->getMessage();
    }

    public function test_peek_returns_null_when_no_socket_data(): void
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn(false);

        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            $this->limits,
            new LdapEncoder(),
        );

        self::assertNull($queue->peekForCancelSignal(2));
    }

    public function test_peek_signals_an_unbind_and_still_leaves_it_to_be_read(): void
    {
        $queue = $this->makeQueueWithEncodedRequest(
            new LdapMessageRequest(3, new UnbindRequest()),
        );

        $signal = $queue->peekForCancelSignal(2);

        self::assertInstanceOf(
            UnbindRequest::class,
            $signal?->getRequest(),
        );
        // The session still ends the way an unbind ends it, so the message must survive the peek.
        self::assertInstanceOf(
            UnbindRequest::class,
            $queue->getMessage()->getRequest(),
        );
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

        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            $this->limits,
            $encoder,
        );

        $buffered = $queue->peekForCancelSignal(2);
        $signal = $queue->peekForCancelSignal(2);

        self::assertNull($buffered);
        self::assertInstanceOf(
            CancelRequest::class,
            $signal?->getRequest(),
        );
    }

    public function test_poll_returns_null_when_nothing_is_waiting(): void
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn(false);

        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            $this->limits,
            new LdapEncoder(),
        );

        self::assertNull($queue->pollMessage());
    }

    public function test_poll_takes_a_buffered_message_before_reading_the_socket_and_holds_neither(): void
    {
        $encoder = new LdapEncoder();
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn(
            $encoder->encode((new LdapMessageRequest(5, new DeleteRequest('dc=foo,dc=bar')))->toAsn1())
                . $encoder->encode((new LdapMessageRequest(6, new DeleteRequest('dc=foo,dc=bar')))->toAsn1()),
            false,
        );
        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            $this->limits,
            $encoder,
        );
        $queue->peekForCancelSignal(2);

        $buffered = $queue->pollMessage();
        $read = $queue->pollMessage();
        $nothing = $queue->pollMessage();

        self::assertSame(
            5,
            $buffered?->getMessageId(),
        );
        self::assertSame(
            6,
            $read?->getMessageId(),
        );
        self::assertNull($nothing);
    }

    public function test_poll_refuses_a_message_carrying_a_zero_message_id(): void
    {
        $queue = $this->makeQueueWithEncodedRequest(
            new LdapMessageRequest(0, new DeleteRequest('dc=foo,dc=bar')),
        );

        self::expectException(RequestValidationException::class);
        self::expectExceptionMessage('The message ID 0 cannot be used in a client request.');

        $queue->pollMessage();
    }

    public function test_encrypt_discards_plaintext_pipelined_behind_the_upgrade(): void
    {
        $encoder = new LdapEncoder();
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn(
            $encoder->encode((new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS)))->toAsn1())
                . $encoder->encode((new LdapMessageRequest(2, new DeleteRequest('dc=foo,dc=bar')))->toAsn1()),
            false,
        );

        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            $this->limits,
            $encoder,
        );

        self::assertSame(
            1,
            $queue->getMessage()->getMessageId(),
        );
        self::assertTrue(
            $queue->hasBufferedInput(),
            'The pipelined second PDU should be buffered ahead of the upgrade.',
        );

        $queue->encrypt();

        self::assertFalse(
            $queue->hasBufferedInput(),
            'Plaintext read before the upgrade must not survive it.',
        );

        $this->expectException(ConnectionException::class);

        $queue->getMessage();
    }

    public function test_it_writes_a_message_larger_than_the_send_buffer_without_an_oversized_write(): void
    {
        $encoder = new LdapEncoder();
        $writes = [];

        $socket = $this->createMock(Socket::class);
        $socket->method('write')
            ->willReturnCallback(function (string $bytes) use (&$writes, $socket): Socket {
                $writes[] = $bytes;

                return $socket;
            });

        $response = new LdapMessageResponse(
            1,
            new DeleteResponse(
                0,
                'dc=foo,dc=bar',
                str_repeat('a', 32768),
            ),
        );

        (new ServerQueue(
            $socket,
            $this->messageDecoder,
            $this->limits,
            $encoder,
        ))->sendMessage($response);

        foreach ($writes as $write) {
            self::assertLessThanOrEqual(
                8192,
                strlen($write),
                'A residual larger than the buffer means the flush left bytes behind to recopy.',
            );
        }

        self::assertSame(
            $encoder->encode($response->toAsn1()),
            implode('', $writes),
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

        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            $this->limits,
            $encoder,
        );

        for ($attempt = 0; $attempt < self::FLOOD_ATTEMPTS; $attempt++) {
            self::assertNull($queue->peekForCancelSignal(2));
        }

        self::assertLessThan(
            self::FLOOD_ATTEMPTS,
            $reads,
        );
    }

    public function test_peek_stops_reading_once_the_pending_requests_reach_the_byte_limit(): void
    {
        $reads = 0;
        $queue = new ServerQueue(
            $this->socketRepeating(
                self::encodedRequestPastTheReadAheadBytes(),
                $reads,
            ),
            $this->messageDecoder,
            $this->limits,
            new LdapEncoder(),
        );

        for ($attempt = 0; $attempt < self::FLOOD_ATTEMPTS; $attempt++) {
            self::assertNull($queue->peekForCancelSignal(2));
        }

        self::assertSame(
            1,
            $reads,
        );
    }

    public function test_peek_reads_again_once_the_pending_requests_are_taken(): void
    {
        $reads = 0;
        $queue = new ServerQueue(
            $this->socketRepeating(
                self::encodedRequestPastTheReadAheadBytes(),
                $reads,
            ),
            $this->messageDecoder,
            $this->limits,
            new LdapEncoder(),
        );

        $queue->peekForCancelSignal(2);
        $queue->peekForCancelSignal(2);
        $queue->getMessage();
        $queue->peekForCancelSignal(2);

        self::assertSame(
            2,
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

        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            $this->limits,
            $encoder,
        );

        // Peek decodes and buffers the DeleteRequest into pendingMessages
        $queue->peekForCancelSignal(2);

        // getMessage() must drain pendingMessages — no second socket read
        $result = $queue->getMessage();

        self::assertInstanceOf(
            DeleteRequest::class,
            $result->getRequest(),
        );
    }

    public function test_a_requeued_message_is_read_before_anything_already_pending(): void
    {
        $queue = $this->makeQueueWithEncodedRequest(
            new LdapMessageRequest(5, new DeleteRequest('dc=foo,dc=bar')),
        );
        $queue->peekForCancelSignal(2);

        $queue->requeue(new LdapMessageRequest(
            6,
            new UnbindRequest(),
        ));

        self::assertSame(
            6,
            $queue->getMessage()->getMessageId(),
        );
        self::assertSame(
            5,
            $queue->getMessage()->getMessageId(),
        );
    }

    public function test_a_buffered_message_is_read_after_those_already_pending(): void
    {
        $queue = $this->makeQueueWithEncodedRequest(
            new LdapMessageRequest(5, new DeleteRequest('dc=foo,dc=bar')),
        );
        $queue->peekForCancelSignal(2);

        $queue->buffer(new LdapMessageRequest(
            6,
            new CancelRequest(2),
        ));

        self::assertSame(
            5,
            $queue->getMessage()->getMessageId(),
        );
        self::assertSame(
            6,
            $queue->getMessage()->getMessageId(),
        );
    }

    public function test_it_should_reject_a_request_whose_declared_length_exceeds_the_max_receive_size(): void
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn(hex2bin('3084000000c8'));

        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            new RequestLimits(
                authorization: $this->authorization,
                maxSize: 100,
            ),
        );

        $this->expectException(RequestSizeExceededException::class);

        $queue->getMessage();
    }

    public function test_it_should_refuse_a_request_holding_more_elements_than_the_limit(): void
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn((new LdapEncoder())->encode(
            (new LdapMessageRequest(
                5,
                new DeleteRequest('dc=foo,dc=bar'),
            ))->toAsn1(),
        ));
        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            new RequestLimits(
                authorization: $this->authorization,
                maxElements: 1,
            ),
        );

        try {
            $queue->getMessage();
            self::fail('The request should have been refused.');
        } catch (RequestSizeExceededException $e) {
            self::assertInstanceOf(
                PduElementsException::class,
                $e->getPrevious(),
            );
        }
    }

    public function test_it_should_decode_a_request_holding_exactly_the_element_limit(): void
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn((new LdapEncoder())->encode(
            (new LdapMessageRequest(
                5,
                new DeleteRequest('dc=foo,dc=bar'),
            ))->toAsn1(),
        ));
        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            new RequestLimits(
                authorization: $this->authorization,
                maxElements: 2,
            ),
        );

        self::assertSame(
            5,
            $queue->getMessage()->getMessageId(),
        );
    }

    public function test_it_should_answer_a_request_whose_nested_parts_run_past_what_the_main_decode_left(): void
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn(self::encodedSortRequest());
        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            new RequestLimits(
                authorization: $this->authorization,
                maxElements: 9,
            ),
        );

        try {
            $queue->getMessage();
            self::fail('The request should have been answered as past the element limit.');
        } catch (MessageDecodeException $e) {
            self::assertSame(
                [5, ResultCode::ADMIN_LIMIT_EXCEEDED],
                [$e->getMessageId(), $e->getResultCode()],
            );
        }
    }

    public function test_it_should_decode_a_request_whose_nested_parts_fit_what_the_main_decode_left(): void
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn(self::encodedSortRequest());
        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            new RequestLimits(
                authorization: $this->authorization,
                maxElements: 10,
            ),
        );

        self::assertSame(
            5,
            $queue->getMessage()->getMessageId(),
        );
    }

    /**
     * @return iterable<string, array{Closure(ServerQueue): mixed}>
     */
    public static function requestReadProvider(): iterable
    {
        yield 'a read' => [static fn(ServerQueue $queue): mixed => $queue->getMessage()];
        yield 'a peek' => [static fn(ServerQueue $queue): mixed => $queue->peekForCancelSignal(2)];
    }

    /**
     * @param Closure(ServerQueue): mixed $read
     */
    #[DataProvider('requestReadProvider')]
    public function test_a_request_nested_past_the_decode_depth_limit_is_a_protocol_failure(Closure $read): void
    {
        $nested = Asn1::null();
        for ($i = 0; $i < 20; $i++) {
            $nested = Asn1::sequence($nested);
        }
        $encoder = new LdapEncoder();
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn($encoder->encode(Asn1::sequence(
            Asn1::integer(1),
            $nested,
        )));

        try {
            $read(new ServerQueue(
                $socket,
                $this->messageDecoder,
                $this->limits,
                $encoder,
            ));
            self::fail('The deeply nested request should have been refused.');
        } catch (ProtocolException $e) {
            self::assertInstanceOf(
                PduDepthException::class,
                $e->getPrevious(),
            );
        }
    }

    public function test_it_should_decode_a_request_within_the_max_receive_size(): void
    {
        $encoder = new LdapEncoder();
        $bytes = $encoder->encode(
            (new LdapMessageRequest(5, new DeleteRequest('dc=foo,dc=bar')))->toAsn1(),
        );

        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn($bytes);

        $queue = new ServerQueue(
            $socket,
            $this->messageDecoder,
            new RequestLimits(
                authorization: $this->authorization,
                maxSize: 5_242_880,
            ),
        );

        self::assertSame(
            5,
            $queue->getMessage()->getMessageId(),
        );
    }

    public function test_it_should_refuse_a_request_past_the_anonymous_size_until_the_session_binds(): void
    {
        $queue = $this->makeQueueWithAnonymousSize(self::encodedSearchPastTheAnonymousSize());

        try {
            $queue->getMessage();
            self::fail('The request should have been refused before the session bound.');
        } catch (RequestSizeExceededException $e) {
            self::assertInstanceOf(
                PduLengthException::class,
                $e->getPrevious(),
            );
        }
        $this->authorization->setToken(new BindToken(AuthzId::fromDn(new Dn('cn=user,dc=foo,dc=bar'))));

        self::assertSame(
            5,
            $queue->getMessage()->getMessageId(),
        );
    }

    public function test_it_should_refuse_a_request_past_the_anonymous_size_once_the_bind_is_reset(): void
    {
        $queue = $this->makeQueueWithAnonymousSize(str_repeat(
            self::encodedSearchPastTheAnonymousSize(),
            2,
        ));
        $this->authorization->setToken(new BindToken(AuthzId::fromDn(new Dn('cn=user,dc=foo,dc=bar'))));
        $queue->getMessage();
        $this->authorization->setToken(new AnonToken());

        $this->expectException(RequestSizeExceededException::class);

        $queue->getMessage();
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
            $this->messageDecoder,
            $this->limits,
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
            $this->messageDecoder,
            $this->limits,
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
            $this->messageDecoder,
            $this->limits,
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
        (new ServerQueue(
            $socket,
            $this->messageDecoder,
            $this->limits,
        ))->sendMessage($message);

        return $written;
    }

    /**
     * Sends a response the socket stalls on, allowing that one write and no other.
     */
    private function failWrite(): WriteTimeoutException
    {
        $failure = new WriteTimeoutException('The write operation timed out after 30 seconds.');
        $this->mockEncoder
            ->method('encode')
            ->willReturn('foo');
        $this->mockSocket
            ->expects(self::once())
            ->method('write')
            ->willThrowException($failure);

        try {
            $this->subject->sendMessage(new LdapMessageResponse(
                1,
                new DeleteResponse(0),
            ));
        } catch (WriteTimeoutException) {
        }

        return $failure;
    }

    private function makeQueueWithEncodedRequest(LdapMessageRequest $message): ServerQueue
    {
        $encoder = new LdapEncoder();
        $bytes = $encoder->encode($message->toAsn1());

        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn($bytes);

        return new ServerQueue(
            $socket,
            $this->messageDecoder,
            $this->limits,
            $encoder,
        );
    }

    /**
     * A socket that hands back the same bytes on every read, counting the reads.
     */
    private function socketRepeating(
        string $bytes,
        int &$reads,
    ): Socket&MockObject {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')
            ->willReturnCallback(function () use ($bytes, &$reads): string {
                $reads++;

                return $bytes;
            });

        return $socket;
    }

    /**
     * A queue whose socket hands out the chunks in turn, throwing any exception among them, and records each timeout.
     *
     * @param list<string|Throwable> $chunks
     * @param list<float|null> $timeouts
     */
    private function queueReading(
        array $chunks,
        array &$timeouts,
        int $readTimeout = 30,
    ): ServerQueue {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')
            ->willReturnCallback(function (bool $block, ?float $timeout) use (&$chunks, &$timeouts): string|false {
                $timeouts[] = $timeout;
                $chunk = array_shift($chunks) ?? false;
                if ($chunk instanceof Throwable) {
                    throw $chunk;
                }

                return $chunk;
            });

        return new ServerQueue(
            $socket,
            $this->messageDecoder,
            new RequestLimits(
                $this->authorization,
                readTimeout: $readTimeout,
            ),
            new LdapEncoder(),
        );
    }

    private static function encodedDelete(int $messageId): string
    {
        return (new LdapEncoder())->encode((new LdapMessageRequest(
            $messageId,
            Operations::delete('cn=foo,dc=foo,dc=bar'),
        ))->toAsn1());
    }

    /**
     * The bytes cut into chunks of the given lengths, then whatever is left.
     *
     * @return list<string>
     */
    private static function chunksOf(
        string $bytes,
        int ...$lengths,
    ): array {
        $chunks = [];
        foreach ($lengths as $length) {
            $chunks[] = substr(
                $bytes,
                0,
                $length,
            );
            $bytes = substr(
                $bytes,
                $length,
            );
        }
        $chunks[] = $bytes;

        return $chunks;
    }

    private function makeQueueWithAnonymousSize(string $bytes): ServerQueue
    {
        $socket = $this->createMock(Socket::class);
        $socket->method('read')->willReturn($bytes);

        return new ServerQueue(
            $socket,
            $this->messageDecoder,
            new RequestLimits(
                authorization: $this->authorization,
                maxSize: 2_621_440,
                maxAnonymousSize: 262_144,
            ),
        );
    }

    /**
     * A search a little over the 256 KiB a session without a bind may send.
     */
    private static function encodedSearchPastTheAnonymousSize(): string
    {
        return (new LdapEncoder())->encode((new LdapMessageRequest(
            5,
            Operations::search(Filters::equal(
                'cn',
                str_repeat(
                    'a',
                    300_000,
                ),
            ))->base('dc=foo,dc=bar'),
        ))->toAsn1());
    }

    /**
     * A modify a little over the 64 KiB read-ahead may buffer.
     */
    private static function encodedRequestPastTheReadAheadBytes(): string
    {
        return (new LdapEncoder())->encode((new LdapMessageRequest(
            5,
            Operations::modify(
                'cn=foo,dc=foo,dc=bar',
                Change::replace(
                    'description',
                    str_repeat(
                        'x',
                        70_000,
                    ),
                ),
            ),
        ))->toAsn1());
    }

    /**
     * A request holding three elements in its main decode and seven in its controls.
     */
    private static function encodedSortRequest(): string
    {
        return (new LdapEncoder())->encode((new LdapMessageRequest(
            5,
            new DeleteRequest('dc=foo,dc=bar'),
            new SortingControl(
                new SortKey('cn'),
                new SortKey('sn'),
            ),
        ))->toAsn1());
    }
}
