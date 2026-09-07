<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\ConnectionException as LdapConnectionException;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RequestSizeExceededException;
use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\DisconnectSender;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\SessionEndPolicy;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Exception\IdleTimeoutException;
use FreeDSx\Socket\Exception\WriteTimeoutException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Throwable;

final class SessionEndPolicyTest extends TestCase
{
    private ServerQueue&MockObject $queue;

    private SessionEndPolicy $subject;

    /**
     * @var list<LdapMessageResponse>
     */
    private array $sent = [];

    protected function setUp(): void
    {
        $this->queue = $this->createMock(ServerQueue::class);
        $this->sent = [];

        $this->queue
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse ...$messages): ServerQueue {
                foreach ($messages as $message) {
                    $this->sent[] = $message;
                }

                return $this->queue;
            });

        $eventLogger = new EventLogger(null);
        $this->subject = new SessionEndPolicy(
            new DisconnectSender(
                $this->queue,
                $eventLogger,
            ),
            $eventLogger,
        );
    }

    /**
     * @return iterable<string, array{Throwable, ?ConnectionObservation}>
     */
    public static function closeReasonProvider(): iterable
    {
        yield 'an unusable message id' => [
            new RequestValidationException('bad id'),
            null,
        ];

        yield 'the client stopped reading' => [
            new WriteTimeoutException('write timed out'),
            ConnectionObservation::WriteTimeout,
        ];

        yield 'the client went quiet' => [
            new IdleTimeoutException('idle too long'),
            ConnectionObservation::IdleTimeout,
        ];

        yield 'an ordinary disconnect' => [
            new ConnectionException('client hung up'),
            null,
        ];

        yield 'an oversized request' => [
            new RequestSizeExceededException('too big'),
            ConnectionObservation::RequestSizeExceeded,
        ];

        yield 'an undecodable pdu' => [
            new ProtocolException('malformed'),
            ConnectionObservation::ProtocolError,
        ];

        yield 'an encoding failure' => [
            new EncoderException('cannot encode'),
            ConnectionObservation::ProtocolError,
        ];

        yield 'a lost dependency' => [
            new LdapConnectionException('upstream gone'),
            ConnectionObservation::Unavailable,
        ];

        yield 'anything else' => [
            new RuntimeException('unexpected'),
            null,
        ];
    }

    #[DataProvider('closeReasonProvider')]
    public function test_it_reports_the_close_reason(
        Throwable $exception,
        ?ConnectionObservation $expected,
    ): void {
        self::assertSame(
            $expected,
            $this->subject->end($exception),
        );
    }

    public function test_it_answers_an_unusable_message_id_with_its_own_diagnostic(): void
    {
        $this->subject->end(new RequestValidationException('the message id was reused'));

        self::assertSame(
            'the message id was reused',
            $this->diagnosticOfOnlyNotice(),
        );
    }

    public function test_it_does_not_leak_a_malformed_pdu_diagnostic_to_the_client(): void
    {
        $this->subject->end(new ProtocolException('BER tag 0x99 at offset 14'));

        self::assertSame(
            'The message could not be processed.',
            $this->diagnosticOfOnlyNotice(),
        );
    }

    public function test_it_answers_a_lost_dependency_as_unavailable(): void
    {
        $this->subject->end(new LdapConnectionException('the upstream is gone'));

        self::assertSame(
            ResultCode::UNAVAILABLE,
            $this->resultCodeOfOnlyNotice(),
        );
    }

    public function test_it_answers_every_other_disconnect_as_a_protocol_error(): void
    {
        $this->subject->end(new RequestSizeExceededException('too big'));

        self::assertSame(
            ResultCode::PROTOCOL_ERROR,
            $this->resultCodeOfOnlyNotice(),
        );
    }

    public function test_it_sends_nothing_for_a_timeout_or_an_ordinary_disconnect(): void
    {
        $this->subject->end(new WriteTimeoutException('write timed out'));
        $this->subject->end(new IdleTimeoutException('idle too long'));
        $this->subject->end(new ConnectionException('client hung up'));

        self::assertSame(
            [],
            $this->sent,
        );
    }

    public function test_it_keeps_quiet_about_an_unexpected_failure_once_the_connection_is_gone(): void
    {
        $this->queue
            ->method('isConnected')
            ->willReturn(false);

        $this->subject->end(new RuntimeException('unexpected'));

        self::assertSame(
            [],
            $this->sent,
        );
    }

    public function test_it_still_answers_an_unexpected_failure_while_the_connection_holds(): void
    {
        $this->queue
            ->method('isConnected')
            ->willReturn(true);

        $this->subject->end(new RuntimeException('unexpected'));

        self::assertSame(
            ResultCode::PROTOCOL_ERROR,
            $this->resultCodeOfOnlyNotice(),
        );
    }

    public function test_it_treats_a_decode_failure_as_an_undecodable_pdu(): void
    {
        $reason = $this->subject->end(new MessageDecodeException(
            1,
            3,
            'bad contents',
        ));

        self::assertSame(
            ConnectionObservation::ProtocolError,
            $reason,
        );
        self::assertSame(
            'The message could not be processed.',
            $this->diagnosticOfOnlyNotice(),
        );
    }

    public function test_it_ends_a_shutdown_as_unavailable(): void
    {
        $this->subject->shuttingDown();

        self::assertSame(
            ResultCode::UNAVAILABLE,
            $this->resultCodeOfOnlyNotice(),
        );
        self::assertSame(
            'The server is shutting down.',
            $this->diagnosticOfOnlyNotice(),
        );
    }

    private function onlyNotice(): ExtendedResponse
    {
        self::assertCount(
            1,
            $this->sent,
        );
        $response = $this->sent[0]->getResponse();
        self::assertInstanceOf(
            ExtendedResponse::class,
            $response,
        );
        self::assertSame(
            ExtendedResponse::OID_NOTICE_OF_DISCONNECTION,
            $response->getName(),
        );

        return $response;
    }

    private function resultCodeOfOnlyNotice(): int
    {
        return $this->onlyNotice()->getResultCode();
    }

    private function diagnosticOfOnlyNotice(): string
    {
        return $this->onlyNotice()->getDiagnosticMessage();
    }
}
