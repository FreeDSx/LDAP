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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue\Response;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\OutOfSequenceResponder;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class OutOfSequenceResponderTest extends TestCase
{
    private ServerQueue&MockObject $queue;

    private RecordingLogger $logger;

    private OutOfSequenceResponder $subject;

    /**
     * @var list<LdapMessageRequest>
     */
    private array $waiting = [];

    /**
     * @var list<LdapMessageResponse>
     */
    private array $sent = [];

    protected function setUp(): void
    {
        $this->queue = $this->createMock(ServerQueue::class);
        $this->queue
            ->method('pollMessage')
            ->willReturnCallback(fn(): ?LdapMessageRequest => array_shift($this->waiting));
        $this->queue
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse ...$responses): ServerQueue {
                array_push(
                    $this->sent,
                    ...$responses,
                );

                return $this->queue;
            });
        $this->logger = new RecordingLogger();

        $this->subject = new OutOfSequenceResponder(
            $this->queue,
            new EventLogger(
                $this->logger,
                EventLogPolicy::all(),
            ),
        );
    }

    #[DataProvider('signalProvider')]
    public function test_a_cancel_or_abandon_naming_the_stream_is_its_signal_and_is_not_answered(RequestInterface $request): void
    {
        $signal = new LdapMessageRequest(
            3,
            $request,
        );
        $this->waiting = [$signal];

        self::assertSame(
            $signal,
            $this->subject->signalOrRefuse(2),
        );
        self::assertSame(
            [],
            $this->sent,
        );
    }

    /**
     * @return iterable<string, array{RequestInterface}>
     */
    public static function signalProvider(): iterable
    {
        yield 'a cancel' => [new CancelRequest(2)];
        yield 'an abandon' => [new AbandonRequest(2)];
    }

    public function test_an_unbind_is_the_signal_and_is_left_for_the_dispatcher(): void
    {
        $unbind = new LdapMessageRequest(
            3,
            new UnbindRequest(),
        );
        $this->waiting = [$unbind];

        $this->queue
            ->expects(self::once())
            ->method('requeue')
            ->with($unbind);

        self::assertSame(
            $unbind,
            $this->subject->signalOrRefuse(2),
        );
        self::assertSame(
            [],
            $this->sent,
        );
    }

    public function test_an_abandon_naming_another_operation_is_dropped_without_a_response(): void
    {
        $this->waiting = [
            new LdapMessageRequest(
                3,
                new AbandonRequest(1),
            ),
        ];

        self::assertNull($this->subject->signalOrRefuse(2));
        self::assertSame(
            [],
            $this->sent,
        );
    }

    #[DataProvider('refusedRequestProvider')]
    public function test_a_request_is_refused_with_an_operations_error_on_its_own_message_id(
        RequestInterface $request,
        string $responseClass,
    ): void {
        $this->waiting = [
            new LdapMessageRequest(
                3,
                $request,
            ),
        ];

        self::assertNull($this->subject->signalOrRefuse(2));
        self::assertCount(
            1,
            $this->sent,
        );
        self::assertSame(
            3,
            $this->sent[0]->getMessageId(),
        );

        $response = $this->sent[0]->getResponse();

        self::assertSame(
            $responseClass,
            $response::class,
        );
        self::assertInstanceOf(
            LdapResult::class,
            $response,
        );
        self::assertSame(
            ResultCode::OPERATIONS_ERROR,
            $response->getResultCode(),
        );
    }

    /**
     * @return iterable<string, array{RequestInterface, class-string}>
     */
    public static function refusedRequestProvider(): iterable
    {
        yield 'a simple bind' => [
            Operations::bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            ),
            BindResponse::class,
        ];
        yield 'a SASL bind' => [
            new SaslBindRequest('PLAIN'),
            BindResponse::class,
        ];
        yield 'a StartTLS' => [
            new ExtendedRequest(ExtendedRequest::OID_START_TLS),
            ExtendedResponse::class,
        ];
        yield 'a WhoAmI' => [
            Operations::whoami(),
            ExtendedResponse::class,
        ];
        yield 'a cancel naming another operation' => [
            new CancelRequest(1),
            ExtendedResponse::class,
        ];
        yield 'a search' => [
            Operations::read('dc=foo,dc=bar'),
            SearchResultDone::class,
        ];
        yield 'a modify' => [
            Operations::modify(
                'dc=foo,dc=bar',
                Change::replace(
                    'description',
                    'foo',
                ),
            ),
            ModifyResponse::class,
        ];
    }

    public function test_every_waiting_request_is_refused_in_one_poll(): void
    {
        $this->waiting = [
            new LdapMessageRequest(
                3,
                Operations::whoami(),
            ),
            new LdapMessageRequest(
                4,
                Operations::whoami(),
            ),
        ];

        self::assertNull($this->subject->signalOrRefuse(2));
        self::assertSame(
            [3, 4],
            array_map(
                static fn(LdapMessageResponse $response): int => $response->getMessageId(),
                $this->sent,
            ),
        );
    }

    public function test_reading_stops_at_a_signal_behind_a_refused_request(): void
    {
        $cancel = new LdapMessageRequest(
            4,
            new CancelRequest(2),
        );
        $later = new LdapMessageRequest(
            5,
            Operations::whoami(),
        );
        $this->waiting = [
            new LdapMessageRequest(
                3,
                Operations::whoami(),
            ),
            $cancel,
            $later,
        ];

        self::assertSame(
            $cancel,
            $this->subject->signalOrRefuse(2),
        );
        self::assertCount(
            1,
            $this->sent,
        );
        self::assertSame(
            [$later],
            $this->waiting,
        );
    }

    #[DataProvider('reusedMessageIdProvider')]
    public function test_a_request_reusing_the_message_id_of_the_stream_ends_the_session(RequestInterface $request): void
    {
        $this->waiting = [
            new LdapMessageRequest(
                2,
                $request,
            ),
        ];

        $this->expectException(RequestValidationException::class);

        $this->subject->signalOrRefuse(2);
    }

    /**
     * @return iterable<string, array{RequestInterface}>
     */
    public static function reusedMessageIdProvider(): iterable
    {
        yield 'a WhoAmI' => [Operations::whoami()];
        yield 'a cancel naming the stream' => [new CancelRequest(2)];
    }

    public function test_a_refusal_is_recorded_as_a_refused_operation(): void
    {
        $this->waiting = [
            new LdapMessageRequest(
                3,
                Operations::whoami(),
            ),
        ];

        $this->subject->signalOrRefuse(2);

        self::assertSame(
            ServerEvent::OperationRefused->value,
            $this->logger->records[0]['context'][EventContext::EVENT] ?? null,
        );
        self::assertSame(
            ResultCode::OPERATIONS_ERROR,
            $this->logger->records[0]['context'][EventContext::RESULT_CODE] ?? null,
        );
    }
}
