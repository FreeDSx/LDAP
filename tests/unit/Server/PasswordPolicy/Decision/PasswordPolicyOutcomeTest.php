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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyOutcomeTest extends TestCase
{
    public function test_allow_has_no_payload(): void
    {
        $outcome = PasswordPolicyOutcome::allow();

        self::assertFalse($outcome->denied);
        self::assertSame(
            ResultCode::SUCCESS,
            $outcome->ldapResultCode,
        );
        self::assertNull($outcome->errorCode);
        self::assertNull($outcome->timeBeforeExpiration);
        self::assertNull($outcome->graceRemaining);
        self::assertFalse($outcome->hasResponseControlPayload());
    }

    public function test_allow_with_expiration_warning(): void
    {
        $outcome = PasswordPolicyOutcome::allowWithExpirationWarning(3600);

        self::assertFalse($outcome->denied);
        self::assertSame(
            3600,
            $outcome->timeBeforeExpiration,
        );
        self::assertNull($outcome->graceRemaining);
        self::assertTrue($outcome->hasResponseControlPayload());
    }

    public function test_allow_with_grace_warning(): void
    {
        $outcome = PasswordPolicyOutcome::allowWithGraceWarning(2);

        self::assertFalse($outcome->denied);
        self::assertSame(
            2,
            $outcome->graceRemaining,
        );
        self::assertNull($outcome->timeBeforeExpiration);
        self::assertTrue($outcome->hasResponseControlPayload());
    }

    public function test_allow_with_error_signals_change_after_reset(): void
    {
        $outcome = PasswordPolicyOutcome::allowWithError(
            PwdPolicyError::CHANGE_AFTER_RESET,
            'reset required',
        );

        self::assertFalse($outcome->denied);
        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $outcome->errorCode,
        );
        self::assertSame(
            'reset required',
            $outcome->diagnostic,
        );
        self::assertTrue($outcome->hasResponseControlPayload());
    }

    public function test_deny_carries_error_code_and_result_code(): void
    {
        $outcome = PasswordPolicyOutcome::deny(
            PwdPolicyError::ACCOUNT_LOCKED,
            ResultCode::INVALID_CREDENTIALS,
            'account locked',
        );

        self::assertTrue($outcome->denied);
        self::assertSame(
            ResultCode::INVALID_CREDENTIALS,
            $outcome->ldapResultCode,
        );
        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $outcome->errorCode,
        );
        self::assertSame(
            'account locked',
            $outcome->diagnostic,
        );
        self::assertTrue($outcome->hasResponseControlPayload());
    }

    public function test_without_error_keeps_the_decision_but_drops_the_error(): void
    {
        $outcome = PasswordPolicyOutcome::deny(
            PwdPolicyError::ACCOUNT_LOCKED,
            ResultCode::INVALID_CREDENTIALS,
            'Invalid credentials.',
        )->withoutError();

        self::assertSame(
            [true, ResultCode::INVALID_CREDENTIALS, null, 'Invalid credentials.'],
            [$outcome->denied, $outcome->ldapResultCode, $outcome->errorCode, $outcome->diagnostic],
        );
        self::assertFalse($outcome->hasResponseControlPayload());
    }
}
