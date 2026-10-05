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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

final class ServerEventTest extends TestCase
{
    private const VALID_LEVELS = [
        LogLevel::EMERGENCY,
        LogLevel::ALERT,
        LogLevel::CRITICAL,
        LogLevel::ERROR,
        LogLevel::WARNING,
        LogLevel::NOTICE,
        LogLevel::INFO,
        LogLevel::DEBUG,
    ];

    public function test_every_case_maps_to_a_valid_psr3_level(): void
    {
        foreach (ServerEvent::cases() as $event) {
            self::assertContains(
                $event->level(),
                self::VALID_LEVELS,
                $event->value,
            );
        }
    }

    public function test_every_case_has_a_readable_message_rather_than_its_name(): void
    {
        foreach (ServerEvent::cases() as $event) {
            self::assertNotSame(
                $event->value,
                $event->messageTemplate(),
                $event->value,
            );
            self::assertStringEndsWith(
                '.',
                $event->messageTemplate(),
                $event->value,
            );
        }
    }

    public function test_every_case_is_named_within_a_group(): void
    {
        foreach (ServerEvent::cases() as $event) {
            self::assertMatchesRegularExpression(
                '/^(ldap|storage|server)\.[a-z_]+(\.[a-z_]+)*$/',
                $event->value,
            );
        }
    }

    public function test_every_server_case_is_enabled_by_default(): void
    {
        $policy = EventLogPolicy::default();

        foreach (ServerEvent::cases() as $event) {
            if (!str_starts_with($event->value, 'server.')) {
                continue;
            }

            self::assertTrue(
                $policy->isEnabled($event),
                $event->value,
            );
        }
    }

    /**
     * @return array<string, array{0: ServerEvent, 1: string}>
     */
    public static function passwordPolicyEventLevels(): array
    {
        return [
            'account_locked is a warning' => [ServerEvent::PasswordPolicyAccountLocked, LogLevel::WARNING],
            'expired is a notice' => [ServerEvent::PasswordPolicyExpired, LogLevel::NOTICE],
            'change_rejected is a notice' => [ServerEvent::PasswordPolicyChangeRejected, LogLevel::NOTICE],
            'account_unlocked is informational' => [ServerEvent::PasswordPolicyAccountUnlocked, LogLevel::INFO],
            'must_change is informational' => [ServerEvent::PasswordPolicyMustChange, LogLevel::INFO],
            'grace_login is informational' => [ServerEvent::PasswordPolicyGraceLogin, LogLevel::INFO],
        ];
    }

    #[DataProvider('passwordPolicyEventLevels')]
    public function test_password_policy_event_log_level(
        ServerEvent $event,
        string $expected,
    ): void {
        self::assertSame(
            $expected,
            $event->level(),
        );
    }

    #[DataProvider('provideExceptionDiscriminationCases')]
    public function test_from_operation_exception_with_fallback_maps_codes_to_events(
        int $resultCode,
        ServerEvent $expected,
    ): void {
        $exception = new OperationException(
            'boom',
            $resultCode,
        );

        self::assertSame(
            $expected,
            ServerEvent::fromOperationException(
                $exception,
                ServerEvent::AuthorizationDeniedWrite,
                ServerEvent::PasswordModifyFailed,
            ),
        );
    }

    public function test_from_operation_exception_returns_null_for_unmatched_codes_when_no_fallback(): void
    {
        $exception = new OperationException(
            'No such object',
            ResultCode::NO_SUCH_OBJECT,
        );

        self::assertNull(ServerEvent::fromOperationException(
            $exception,
            ServerEvent::AuthorizationDeniedWrite,
        ));
    }

    /**
     * @return array<string, array{int, ServerEvent}>
     */
    public static function provideExceptionDiscriminationCases(): array
    {
        return [
            'insufficient access rights = denial event' => [
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                ServerEvent::AuthorizationDeniedWrite,
            ],
            'unavailable critical extension' => [
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                ServerEvent::CriticalControlRejected,
            ],
            'schema code falls through to fallback' => [
                ResultCode::OBJECT_CLASS_VIOLATION,
                ServerEvent::PasswordModifyFailed,
            ],
            'other code = fallback' => [
                ResultCode::OTHER,
                ServerEvent::PasswordModifyFailed,
            ],
        ];
    }
}
