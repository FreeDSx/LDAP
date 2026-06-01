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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RequestSizeExceededException;
use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Exception\ResponseAlreadySentException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Exception\WriteTimeoutException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\Middleware\StubMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\ThrowingMiddlewareHandler;

final class ServerProtocolHandlerTest extends TestCase
{
    private ServerQueue&MockObject $mockQueue;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockQueue
            ->method('isConnected')
            ->willReturn(true);
        $this->mockQueue
            ->method('sendMessage')
            ->willReturnSelf();
    }

    public function test_it_delegates_each_message_to_the_request_pipeline(): void
    {
        $this->queueReturns([
            new LdapMessageRequest(1, new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true)),
        ]);

        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        $this->handlerWith(new StubMiddlewareHandler(OperationOutcomeResult::succeeded()))
            ->handle();
    }

    public function test_a_request_validation_failure_sends_a_notice_of_disconnect(): void
    {
        $this->queueReturns([
            new LdapMessageRequest(1, new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true)),
        ]);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(new LdapMessageResponse(
                0,
                new ExtendedResponse(
                    new LdapResult(
                        ResultCode::PROTOCOL_ERROR,
                        '',
                        'The message ID 1 is not valid.',
                    ),
                    ExtendedResponse::OID_NOTICE_OF_DISCONNECTION,
                ),
            )));

        $this->handlerWith(new ThrowingMiddlewareHandler(
            new RequestValidationException('The message ID 1 is not valid.'),
        ))->handle();
    }

    public function test_a_pre_pipeline_operation_error_is_answered_and_the_session_stays_open(): void
    {
        $captured = [];
        $this->mockQueue
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse $response) use (&$captured): ServerQueue {
                $captured[] = $response;

                return $this->mockQueue;
            });
        $this->queueReturns([
            new LdapMessageRequest(1, new ModifyDnRequest('cn=a,dc=bar', 'cn=b', true)),
            new LdapMessageRequest(2, new ModifyDnRequest('cn=c,dc=bar', 'cn=d', true)),
        ]);

        $this->handlerWith(new ThrowingMiddlewareHandler(new OperationException(
            'Authentication required.',
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
        )))->handle();

        // Both messages were answered — the connection was not torn down after the first failure.
        self::assertEquals(
            [
                new LdapMessageResponse(1, new ModifyDnResponse(
                    ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                    '',
                    'Authentication required.',
                )),
                new LdapMessageResponse(2, new ModifyDnResponse(
                    ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                    '',
                    'Authentication required.',
                )),
            ],
            $captured,
        );
    }

    public function test_it_does_not_resend_when_a_handler_already_sent_the_response(): void
    {
        $this->queueReturns([
            new LdapMessageRequest(1, new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true)),
        ]);

        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        $this->handlerWith(new ThrowingMiddlewareHandler(new ResponseAlreadySentException()))
            ->handle();
    }

    public function test_it_sends_a_notice_of_disconnect_on_a_protocol_exception_from_the_message_queue(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new ProtocolException());

        $this->expectNoticeOfDisconnect('The message could not be processed.');

        $this->handlerWith(new StubMiddlewareHandler(OperationOutcomeResult::succeeded()))
            ->handle();
    }

    public function test_it_sends_a_notice_of_disconnect_when_a_request_exceeds_the_max_size(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new RequestSizeExceededException('too big'));

        $this->expectNoticeOfDisconnect('The message could not be processed.');

        $this->handlerWith(new StubMiddlewareHandler(OperationOutcomeResult::succeeded()))
            ->handle();
    }

    public function test_it_sends_a_notice_of_disconnect_on_an_encoder_exception_from_the_message_queue(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new EncoderException());

        $this->expectNoticeOfDisconnect('The message could not be processed.');

        $this->handlerWith(new StubMiddlewareHandler(OperationOutcomeResult::succeeded()))
            ->handle();
    }

    public function test_it_ends_normally_on_a_socket_exception_from_the_message_queue(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new ConnectionException('Foo'));

        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        $this->handlerWith(new StubMiddlewareHandler(OperationOutcomeResult::succeeded()))
            ->handle();
    }

    public function test_a_write_timeout_is_recorded_and_closes_without_a_notice_of_disconnect(): void
    {
        $recordingLogger = new RecordingLogger();
        $this->queueReturns([
            new LdapMessageRequest(1, new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true)),
        ]);

        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');
        $this->mockQueue
            ->expects(self::once())
            ->method('close');

        $this->handlerWith(
            new ThrowingMiddlewareHandler(new WriteTimeoutException('The write operation timed out after 600 seconds.')),
            new EventLogger($recordingLogger, EventLogPolicy::default()),
        )->handle();

        $record = $this->findRecord($recordingLogger, 'session.write_timeout');
        self::assertSame(
            'The write operation timed out after 600 seconds.',
            $record['context']['reason_message'],
        );
    }

    public function test_it_sends_a_notice_of_disconnect_and_closes_the_queue_on_shutdown(): void
    {
        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(new LdapMessageResponse(
                0,
                new ExtendedResponse(
                    new LdapResult(ResultCode::UNAVAILABLE, '', 'The server is shutting down.'),
                    ExtendedResponse::OID_NOTICE_OF_DISCONNECTION,
                ),
            )));
        $this->mockQueue
            ->expects(self::once())
            ->method('close');

        $this->handlerWith(new StubMiddlewareHandler(OperationOutcomeResult::succeeded()))
            ->shutdown();
    }

    public function test_an_unexpected_throwable_emits_a_notice_of_disconnect_with_exception_context(): void
    {
        $recordingLogger = new RecordingLogger();
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new RuntimeException('boom'));

        $this->handlerWith(
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
            new EventLogger($recordingLogger, EventLogPolicy::default()),
        )->handle();

        $record = $this->findRecord($recordingLogger, 'session.disconnect_notice');
        self::assertSame(
            RuntimeException::class,
            $record['context']['exception_class'],
        );
        self::assertSame(
            'boom',
            $record['context']['exception_message'],
        );
        self::assertArrayNotHasKey(
            'exception_trace',
            $record['context'],
            'Trace must not appear with the default policy.',
        );
    }

    public function test_an_unexpected_throwable_includes_the_trace_when_policy_opts_in(): void
    {
        $recordingLogger = new RecordingLogger();
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new RuntimeException('boom'));

        $this->handlerWith(
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
            new EventLogger($recordingLogger, EventLogPolicy::default()->withExceptionTraces()),
        )->handle();

        $record = $this->findRecord($recordingLogger, 'session.disconnect_notice');
        self::assertNotEmpty($record['context']['exception_trace']);
    }

    public function test_a_write_timeout_is_logged_without_a_notice_of_disconnect(): void
    {
        $recordingLogger = new RecordingLogger();
        $this->queueReturns([
            new LdapMessageRequest(1, new ModifyDnRequest('cn=a,dc=bar', 'cn=b', true)),
        ]);

        $this->handlerWith(
            new ThrowingMiddlewareHandler(new WriteTimeoutException('The write operation timed out after 600 seconds.')),
            new EventLogger($recordingLogger, EventLogPolicy::default()),
        )->handle();

        $record = $this->findRecord($recordingLogger, 'session.write_timeout');
        self::assertSame(
            'The write operation timed out after 600 seconds.',
            $record['context'][EventContext::REASON_MESSAGE],
        );

        foreach ($recordingLogger->records as $logged) {
            self::assertNotSame(
                'session.disconnect_notice',
                $logged['message'],
                'A stalled reader must not be sent a Notice of Disconnection.',
            );
        }
    }

    /**
     * @param list<LdapMessageRequest> $messages
     */
    private function queueReturns(array $messages): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willReturnCallback(static function () use (&$messages): LdapMessageRequest {
                if ($messages === []) {
                    throw new ConnectionException();
                }

                return array_shift($messages);
            });
    }

    private function handlerWith(
        MiddlewareHandlerInterface $pipeline,
        ?EventLogger $eventLogger = null,
    ): ServerProtocolHandler {
        return new ServerProtocolHandler(
            $this->mockQueue,
            $pipeline,
            $eventLogger ?? new EventLogger(null),
        );
    }

    private function expectNoticeOfDisconnect(string $message): void
    {
        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(new LdapMessageResponse(
                0,
                new ExtendedResponse(
                    new LdapResult(ResultCode::PROTOCOL_ERROR, '', $message),
                    ExtendedResponse::OID_NOTICE_OF_DISCONNECTION,
                ),
            )));
    }

    /**
     * @return array{level: string, message: string, context: array<string, mixed>}
     */
    private function findRecord(
        RecordingLogger $logger,
        string $event,
    ): array {
        foreach ($logger->records as $record) {
            if ($record['message'] === $event) {
                return $record;
            }
        }

        self::fail(sprintf('No record found for event "%s".', $event));
    }
}
