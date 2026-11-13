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

use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\RequestRefusedException;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\DecodeFailureResponder;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class DecodeFailureResponderTest extends TestCase
{
    private ServerQueue&MockObject $queue;

    private ServerAuthorization $authorization;

    private RecordingLogger $logger;

    private DecodeFailureResponder $subject;

    protected function setUp(): void
    {
        $this->queue = $this->createMock(ServerQueue::class);
        $this->authorization = new ServerAuthorization(TestServerOptions::defaults());
        $this->logger = new RecordingLogger();
        $this->subject = new DecodeFailureResponder(
            $this->queue,
            $this->authorization,
            new EventLogger(
                $this->logger,
                EventLogPolicy::all(),
            ),
        );
    }

    public function test_a_request_refused_for_room_is_answered_with_its_result_code_on_its_message_id(): void
    {
        $this->queue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(new LdapMessageResponse(
                3,
                new SearchResultDone(
                    ResultCode::BUSY,
                    diagnosticMessage: 'The server is too busy to hold the request.',
                ),
            )));

        self::assertTrue($this->subject->answer(new RequestRefusedException(
            3,
            3,
            'The server is too busy to hold the request.',
            resultCode: ResultCode::BUSY,
        )));
    }

    public function test_a_request_refused_for_room_is_recorded_as_a_refused_operation(): void
    {
        $this->subject->answer(new RequestRefusedException(
            3,
            3,
            'The server is too busy to hold the request.',
            resultCode: ResultCode::BUSY,
        ));

        self::assertSame(
            [ServerEvent::OperationRefused->value, ResultCode::BUSY],
            [
                $this->logger->records[0]['context'][EventContext::EVENT] ?? null,
                $this->logger->records[0]['context'][EventContext::RESULT_CODE] ?? null,
            ],
        );
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function noResponseProvider(): iterable
    {
        yield 'abandon' => [16];
        yield 'unbind' => [2];
    }

    #[DataProvider('noResponseProvider')]
    public function test_a_request_with_no_response_refused_for_room_is_recorded_and_dropped(int $operationTag): void
    {
        $this->queue
            ->expects(self::never())
            ->method('sendMessage');

        self::assertSame(
            [true, [ServerEvent::OperationRefused->value]],
            [
                $this->subject->answer(new RequestRefusedException(
                    3,
                    $operationTag,
                    'The server is too busy to hold the request.',
                    resultCode: ResultCode::BUSY,
                )),
                $this->logger->events(),
            ],
        );
    }

    #[DataProvider('noResponseProvider')]
    public function test_a_malformed_request_with_no_response_is_not_answered(int $operationTag): void
    {
        $this->queue
            ->expects(self::never())
            ->method('sendMessage');

        self::assertFalse($this->subject->answer(new MessageDecodeException(
            3,
            $operationTag,
            'The request is malformed.',
        )));
    }

    public function test_a_malformed_request_is_recorded_as_a_decode_failure(): void
    {
        $this->subject->answer(new MessageDecodeException(
            3,
            3,
            'The search request is malformed.',
        ));

        self::assertSame(
            [ServerEvent::MessageDecodeFailed->value],
            $this->logger->events(),
        );
    }

    public function test_a_malformed_request_is_answered_on_its_message_id(): void
    {
        $this->queue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(new LdapMessageResponse(
                3,
                new SearchResultDone(
                    ResultCode::PROTOCOL_ERROR,
                    diagnosticMessage: 'The search request is malformed.',
                ),
            )));

        self::assertTrue($this->subject->answer(new MessageDecodeException(
            3,
            3,
            'The search request is malformed.',
        )));
    }

    public function test_a_malformed_request_carrying_message_id_zero_is_not_answered(): void
    {
        $this->queue
            ->expects(self::never())
            ->method('sendMessage');

        self::assertFalse($this->subject->answer(new MessageDecodeException(
            0,
            3,
            'The search request is malformed.',
        )));
    }

    public function test_a_bind_that_fails_to_decode_leaves_the_session_anonymous(): void
    {
        $this->authorization->setToken(BindToken::fromDn('cn=user,dc=foo,dc=bar'));

        $this->subject->answer(new MessageDecodeException(
            2,
            0,
            'The request holds more elements than the server allows.',
            resultCode: ResultCode::ADMIN_LIMIT_EXCEEDED,
        ));

        self::assertInstanceOf(
            AnonToken::class,
            $this->authorization->getToken(),
        );
    }

    public function test_another_request_that_fails_to_decode_keeps_the_sessions_bind(): void
    {
        $token = BindToken::fromDn('cn=user,dc=foo,dc=bar');
        $this->authorization->setToken($token);

        $this->subject->answer(new MessageDecodeException(
            2,
            3,
            'The request holds more elements than the server allows.',
            resultCode: ResultCode::ADMIN_LIMIT_EXCEEDED,
        ));

        self::assertSame(
            $token,
            $this->authorization->getToken(),
        );
    }
}
