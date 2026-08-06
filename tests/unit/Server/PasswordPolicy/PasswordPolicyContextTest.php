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
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyContextTest extends TestCase
{
    public function test_starts_with_no_outcome(): void
    {
        $context = new PasswordPolicyContext();

        self::assertNull($context->getOutcome());
        self::assertNull($context->buildResponseControl());
    }

    public function test_set_then_get_round_trips(): void
    {
        $context = new PasswordPolicyContext();
        $outcome = PasswordPolicyOutcome::allowWithGraceWarning(2);

        $context->setOutcome($outcome);

        self::assertSame(
            $outcome,
            $context->getOutcome(),
        );
    }

    public function test_clear_removes_stashed_outcome(): void
    {
        $context = new PasswordPolicyContext();
        $context->setResponseRequested(true);
        $context->setOutcome(PasswordPolicyOutcome::allowWithGraceWarning(2));

        $context->clear();

        self::assertNull($context->getOutcome());
        self::assertNull($context->buildResponseControl());
    }

    /**
     * Otherwise a failed bind reports that an account exists and is locked to a client that asked for nothing.
     */
    public function test_build_response_control_is_withheld_when_the_client_did_not_ask(): void
    {
        $context = new PasswordPolicyContext();
        $context->setOutcome(PasswordPolicyOutcome::allowWithError(PwdPolicyError::ACCOUNT_LOCKED));

        self::assertNull($context->buildResponseControl());
    }

    public function test_build_response_control_omits_payload_free_outcome(): void
    {
        $context = new PasswordPolicyContext();
        $context->setOutcome(PasswordPolicyOutcome::allow());

        self::assertNull($context->buildResponseControl());
    }

    public function test_build_response_control_includes_grace_remaining(): void
    {
        $context = new PasswordPolicyContext();
        $context->setResponseRequested(true);
        $context->setOutcome(PasswordPolicyOutcome::allowWithGraceWarning(3));

        $control = $context->buildResponseControl();

        self::assertNotNull($control);
        self::assertSame(
            3,
            $control->getGraceAttemptsRemaining(),
        );
        self::assertNull($control->getTimeBeforeExpiration());
        self::assertNull($control->getError());
    }

    public function test_build_response_control_includes_time_before_expiration(): void
    {
        $context = new PasswordPolicyContext();
        $context->setResponseRequested(true);
        $context->setOutcome(PasswordPolicyOutcome::allowWithExpirationWarning(86400));

        $control = $context->buildResponseControl();

        self::assertNotNull($control);
        self::assertSame(
            86400,
            $control->getTimeBeforeExpiration(),
        );
        self::assertNull($control->getGraceAttemptsRemaining());
    }

    public function test_build_response_control_includes_error_code(): void
    {
        $context = new PasswordPolicyContext();
        $context->setResponseRequested(true);
        $context->setOutcome(PasswordPolicyOutcome::allowWithError(PwdPolicyError::CHANGE_AFTER_RESET));

        $control = $context->buildResponseControl();

        self::assertNotNull($control);
        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $control->getError(),
        );
    }
}
