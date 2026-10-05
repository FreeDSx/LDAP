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

namespace Tests\Unit\FreeDSx\Ldap\Server\Logging;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

final class EventLoggerTest extends TestCase
{
    private LoggerInterface&MockObject $mockLogger;

    protected function setUp(): void
    {
        $this->mockLogger = $this->createMock(LoggerInterface::class);
    }

    public function test_record_is_a_no_op_when_logger_is_null(): void
    {
        $subject = new EventLogger(
            null,
            EventLogPolicy::all(),
        );

        $this->expectNotToPerformAssertions();
        $subject->record(
            ServerEvent::BindSuccess,
            ['username' => 'alice'],
        );
    }

    public function test_record_skips_disabled_events(): void
    {
        $this->mockLogger
            ->expects(self::never())
            ->method('log');

        $subject = new EventLogger(
            $this->mockLogger,
            EventLogPolicy::none(),
        );

        $subject->record(
            ServerEvent::BindSuccess,
            ['username' => 'alice'],
        );
    }

    public function test_record_emits_enabled_event_with_level_template_and_merged_context(): void
    {
        $this->mockLogger
            ->expects(self::once())
            ->method('log')
            ->with(
                LogLevel::INFO,
                ServerEvent::BindSuccess->messageTemplate(),
                [
                    'pid' => 4242,
                    'username' => 'alice',
                    'event' => ServerEvent::BindSuccess->value,
                ],
            );

        $subject = new EventLogger(
            $this->mockLogger,
            EventLogPolicy::default(),
            ['pid' => 4242],
        );

        $subject->record(
            ServerEvent::BindSuccess,
            ['username' => 'alice'],
        );
    }

    public function test_record_includes_authorized_by_for_a_proxied_subject(): void
    {
        $token = BindToken::fromDn(
            'cn=alice,dc=example,dc=com',
            3,
            new Dn('cn=admin,dc=example,dc=com'),
        );

        $this->mockLogger
            ->expects(self::once())
            ->method('log')
            ->with(
                self::anything(),
                self::anything(),
                self::callback(
                    static fn(array $context): bool => $context[EventContext::SUBJECT] === [
                        EventContext::USERNAME => 'cn=alice,dc=example,dc=com',
                        EventContext::DN => 'cn=alice,dc=example,dc=com',
                    ]
                        && $context[EventContext::AUTHORIZED_BY] === [
                            EventContext::DN => 'cn=admin,dc=example,dc=com',
                        ],
                ),
            );

        $subject = new EventLogger(
            $this->mockLogger,
            EventLogPolicy::all(),
        );

        $subject->record(
            ServerEvent::SearchAuthorized,
            subject: $token,
        );
    }

    public function test_record_omits_authorized_by_for_a_non_proxied_subject(): void
    {
        $token = BindToken::fromDn(
            'cn=alice,dc=example,dc=com',
        );

        $this->mockLogger
            ->expects(self::once())
            ->method('log')
            ->with(
                self::anything(),
                self::anything(),
                self::callback(
                    static fn(array $context): bool => !array_key_exists(
                        EventContext::AUTHORIZED_BY,
                        $context,
                    ),
                ),
            );

        $subject = new EventLogger(
            $this->mockLogger,
            EventLogPolicy::all(),
        );

        $subject->record(
            ServerEvent::SearchAuthorized,
            subject: $token,
        );
    }

    public function test_call_site_context_keys_win_over_connection_context(): void
    {
        $this->mockLogger
            ->expects(self::once())
            ->method('log')
            ->with(
                self::anything(),
                self::anything(),
                self::callback(
                    static fn(array $context): bool => $context['pid'] === 999
                        && $context['event'] === ServerEvent::BindSuccess->value,
                ),
            );

        $subject = new EventLogger(
            $this->mockLogger,
            EventLogPolicy::default(),
            ['pid' => 4242],
        );

        $subject->record(
            ServerEvent::BindSuccess,
            ['pid' => 999],
        );
    }

    public function test_with_context_returns_a_new_instance_and_does_not_mutate(): void
    {
        $original = new EventLogger(
            $this->mockLogger,
            EventLogPolicy::default(),
            ['pid' => 4242],
        );
        $scoped = $original->withContext(['conn_id' => 7]);

        self::assertNotSame(
            $original,
            $scoped,
        );

        $this->mockLogger
            ->expects(self::exactly(2))
            ->method('log')
            ->willReturnCallback(function (string $level, string $message, array $context): void {
                self::assertArrayHasKey(
                    'event',
                    $context,
                );

                if ($context['event'] === ServerEvent::BindAnonymous->value) {
                    self::assertSame(
                        ['pid' => 4242, 'version' => 3, 'event' => ServerEvent::BindAnonymous->value],
                        $context,
                    );
                    return;
                }

                self::assertSame(
                    ['pid' => 4242, 'conn_id' => 7, 'username' => 'alice', 'event' => ServerEvent::BindSuccess->value],
                    $context,
                );
            });

        $scoped->record(
            ServerEvent::BindSuccess,
            ['username' => 'alice'],
        );
        $original->record(
            ServerEvent::BindAnonymous,
            ['version' => 3],
        );
    }

    public function test_is_enabled_returns_false_when_logger_is_null(): void
    {
        $subject = new EventLogger(
            null,
            EventLogPolicy::all(),
        );

        self::assertFalse($subject->isEnabled(ServerEvent::BindSuccess));
    }

    public function test_is_enabled_reflects_policy(): void
    {
        $subject = new EventLogger(
            $this->mockLogger,
            EventLogPolicy::none()->enable(ServerEvent::BindFailure),
        );

        self::assertTrue($subject->isEnabled(ServerEvent::BindFailure));
        self::assertFalse($subject->isEnabled(ServerEvent::BindSuccess));
    }

    public function test_failure_events_use_psr3_notice_level(): void
    {
        $this->mockLogger
            ->expects(self::once())
            ->method('log')
            ->with(
                LogLevel::NOTICE,
                ServerEvent::BindFailure->messageTemplate(),
                self::anything(),
            );

        $subject = new EventLogger(
            $this->mockLogger,
            EventLogPolicy::default(),
        );

        $subject->record(ServerEvent::BindFailure);
    }

    public function test_exception_context_returns_empty_array_for_null_cause(): void
    {
        $subject = new EventLogger(
            $this->mockLogger,
            EventLogPolicy::default(),
        );

        self::assertSame(
            [],
            $subject->exceptionContextFor(null),
        );
    }

    public function test_exception_context_returns_class_message_origin_without_trace_by_default(): void
    {
        $subject = new EventLogger(
            $this->mockLogger,
            EventLogPolicy::default(),
        );
        $exception = new \RuntimeException('boom');

        $context = $subject->exceptionContextFor($exception);

        self::assertSame(
            \RuntimeException::class,
            $context['exception_class'],
        );
        self::assertSame(
            'boom',
            $context['exception_message'],
        );
        self::assertSame(
            $exception->getFile() . ':' . $exception->getLine(),
            $context['exception_origin'],
        );
        self::assertArrayNotHasKey(
            'exception_trace',
            $context,
            'Trace must not appear unless the policy opts in.',
        );
    }

    public function test_exception_context_includes_trace_when_policy_opts_in(): void
    {
        $subject = new EventLogger(
            $this->mockLogger,
            EventLogPolicy::default()->withExceptionTraces(),
        );
        $exception = new \RuntimeException('boom');

        $context = $subject->exceptionContextFor($exception);

        self::assertSame(
            $exception->getTraceAsString(),
            $context['exception_trace'],
        );
    }
}
