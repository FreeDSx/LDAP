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

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\HistoryEntry;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordExpirationRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Server\PasswordPolicy\UniquePolicyTimeFactory;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;
use Tests\Support\FreeDSx\Ldap\Server\PasswordPolicy\RecordingPasswordChangeConstraint;

final class PasswordPolicyEngineTest extends TestCase
{
    private const NOW = '2026-05-20T12:00:00Z';

    private FrozenClock $clock;

    private UniquePolicyTimeFactory&MockObject $uniqueTimes;

    private PasswordPolicyEngine $subject;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString(self::NOW);
        $this->uniqueTimes = $this->createMock(UniquePolicyTimeFactory::class);

        // Return the plain frozen instant so generated failure/grace values are the second stamped with .000000.
        $this->uniqueTimes
            ->method('next')
            ->willReturnCallback(fn(): DateTimeImmutable => $this->clock->now());

        $this->subject = new PasswordPolicyEngine(
            clock: $this->clock,
            changeConstraints: new PasswordChangeConstraintChain([]),
            uniqueTimes: $this->uniqueTimes,
        );
    }

    public function test_evaluatePreBind_unlocked_account_allows(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(),
            new PasswordPolicy(),
        );

        self::assertFalse($outcome->denied);
    }

    public function test_evaluatePreBind_permanently_locked_denies(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(permanentlyLocked: true),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    duration: 3600,
                ),
            ),
        );

        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $outcome->errorCode,
        );
        self::assertSame(
            ResultCode::INVALID_CREDENTIALS,
            $outcome->ldapResultCode,
        );
    }

    public function test_evaluatePreBind_locked_without_duration_denies(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(accountLockedAt: $this->minutesAgo(5)),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(enabled: true),
            ),
        );

        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $outcome->errorCode,
        );
    }

    public function test_evaluatePreBind_locked_within_duration_denies(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(accountLockedAt: $this->minutesAgo(5)),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    duration: 3600,
                ),
            ),
        );

        self::assertTrue($outcome->denied);
    }

    public function test_evaluatePreBind_locked_past_duration_allows(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(accountLockedAt: $this->minutesAgo(120)),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    duration: 3600,
                ),
            ),
        );

        self::assertFalse($outcome->denied);
    }

    public function test_evaluatePreBind_idle_account_is_locked(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(
                changedAt: $this->minutesAgo(120),
                lastSuccess: $this->minutesAgo(120),
            ),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(maxIdle: 3600),
            ),
        );

        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $outcome->errorCode,
        );
    }

    /**
     * §7.1 locks on reaching pwdMaxIdle, so the boundary second is already too idle.
     */
    public function test_evaluatePreBind_idle_locks_exactly_at_max_idle(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(lastSuccess: $this->minutesAgo(60)),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(maxIdle: 3600),
            ),
        );

        self::assertTrue($outcome->denied);
    }

    /**
     * §7.1 locks when the current time reaches pwdEndTime, not the second after it.
     */
    public function test_evaluatePreBind_denies_exactly_at_the_end_time(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(endTime: $this->clock->now()),
            new PasswordPolicy(),
        );

        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::PASSWORD_EXPIRED,
            $outcome->errorCode,
        );
    }

    /**
     * draft-behera-11 §7.1 counts idleness from pwdLastSuccess, so changing the password does not refresh it.
     */
    public function test_evaluatePreBind_idle_baseline_ignores_a_recent_password_change(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(
                changedAt: $this->minutesAgo(1),
                lastSuccess: $this->minutesAgo(120),
            ),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(maxIdle: 3600),
            ),
        );

        self::assertTrue($outcome->denied);
    }

    /**
     * §7.1 falls back to pwdChangedTime only when no successful bind has been recorded.
     */
    public function test_evaluatePreBind_idle_baseline_falls_back_to_the_change_time(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(changedAt: $this->minutesAgo(1)),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(maxIdle: 3600),
            ),
        );

        self::assertFalse($outcome->denied);
    }

    public function test_recordBindFailure_appends_failure_time(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        $change = $this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
        );
        self::assertSame(
            [GeneralizedTime::formatWithFraction($this->clock->now())],
            $change->getAttribute()->getValues(),
        );
    }

    public function test_recordBindFailure_trims_failures_outside_interval(): void
    {
        $stale = $this->minutesAgo(120);
        $recent = $this->minutesAgo(2);

        $result = $this->subject->recordBindFailure(
            new UserPasswordState(failureTimes: [
                $stale,
                $recent,
            ]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 5,
                    failureCountInterval: 3600,
                ),
            ),
        );

        $change = $this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
        );
        self::assertSame(
            [
                GeneralizedTime::formatWithFraction($recent),
                GeneralizedTime::formatWithFraction($this->clock->now()),
            ],
            $change->getAttribute()->getValues(),
        );
    }

    public function test_recordBindFailure_at_threshold_trips_lockout(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(failureTimes: [
                $this->minutesAgo(3),
                $this->minutesAgo(2),
            ]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                ),
            ),
        );

        self::assertTrue($result->outcome->denied);
        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $result->outcome->errorCode,
        );
        $lockChange = $this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        );
        self::assertSame(
            [GeneralizedTime::format($this->clock->now())],
            $lockChange->getAttribute()->getValues(),
        );
    }

    public function test_recordBindFailure_below_threshold_does_not_lock(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(failureTimes: [$this->minutesAgo(2)]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        self::assertNull($this->findChangeOrNull(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        ));
    }

    public function test_recordBindFailure_lockout_disabled_never_trips(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(failureTimes: [
                $this->minutesAgo(3),
                $this->minutesAgo(2),
            ]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: false,
                    maxFailure: 3,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        self::assertNull($this->findChangeOrNull(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        ));
    }

    public function test_recordBindFailure_already_locked_does_not_re_lock(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(
                accountLockedAt: $this->minutesAgo(5),
                failureTimes: [
                    $this->minutesAgo(3),
                    $this->minutesAgo(2),
                ],
            ),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        self::assertNull($this->findChangeOrNull(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        ));
    }

    public function test_recordBindFailure_first_failure_delays_by_min_delay(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    minDelay: 2,
                    maxDelay: 60,
                ),
            ),
        );

        self::assertSame(
            2.0,
            $result->delaySeconds,
        );
    }

    public function test_recordBindFailure_delay_doubles_with_each_failure(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(failureTimes: [
                $this->minutesAgo(3),
                $this->minutesAgo(2),
            ]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    minDelay: 2,
                    maxDelay: 60,
                ),
            ),
        );

        self::assertSame(
            8.0,
            $result->delaySeconds,
        );
    }

    public function test_recordBindFailure_delay_is_capped_at_max_delay(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(failureTimes: [
                $this->minutesAgo(6),
                $this->minutesAgo(5),
                $this->minutesAgo(4),
                $this->minutesAgo(3),
                $this->minutesAgo(2),
            ]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    minDelay: 5,
                    maxDelay: 20,
                ),
            ),
        );

        self::assertSame(
            20.0,
            $result->delaySeconds,
        );
    }

    public function test_recordBindFailure_no_delay_when_delays_unset(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                ),
            ),
        );

        self::assertSame(
            0.0,
            $result->delaySeconds,
        );
    }

    public function test_recordBindFailure_no_delay_when_max_delay_unset(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    minDelay: 5,
                ),
            ),
        );

        self::assertSame(
            0.0,
            $result->delaySeconds,
        );
    }

    public function test_recordBindSuccess_stamps_last_success(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(),
            new PasswordPolicy(),
        );

        self::assertFalse($result->outcome->denied);
        self::assertSame(
            GeneralizedTime::format($this->clock->now()),
            $this->findChange(
                $result->changes->changes,
                PasswordPolicyOid::NAME_PWD_LAST_SUCCESS,
            )->getAttribute()->firstValue(),
        );
    }

    public function test_recordBindSuccess_clears_prior_failures_and_lock(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(
                accountLockedAt: $this->minutesAgo(120),
                failureTimes: [$this->minutesAgo(5)],
            ),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    duration: 3600,
                ),
            ),
        );

        self::assertTrue($this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
        )->isReset());
        self::assertTrue($this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        )->isReset());
    }

    public function test_recordBindSuccess_does_not_clear_permanent_lock(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(permanentlyLocked: true),
            new PasswordPolicy(),
        );

        self::assertNull($this->findChangeOrNull(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        ));
    }

    public function test_recordBindSuccess_expired_with_no_grace_denies(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(changedAt: $this->minutesAgo(120)),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(maxAge: 3600),
            ),
        );

        self::assertTrue($result->outcome->denied);
        self::assertSame(
            PwdPolicyError::PASSWORD_EXPIRED,
            $result->outcome->errorCode,
        );
        self::assertTrue($result->changes->isEmpty());
    }

    public function test_recordBindSuccess_expired_within_grace_returns_remaining(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(changedAt: $this->minutesAgo(120)),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    graceAuthnLimit: 3,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        self::assertSame(
            2,
            $result->outcome->graceRemaining,
        );
        $graceChange = $this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME,
        );
        self::assertSame(
            [GeneralizedTime::formatWithFraction($this->clock->now())],
            $graceChange->getAttribute()->getValues(),
        );
    }

    public function test_recordBindSuccess_within_warning_returns_seconds_remaining(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(changedAt: $this->minutesAgo(50)),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    expireWarning: 1200,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        self::assertSame(
            600,
            $result->outcome->timeBeforeExpiration,
        );
    }

    public function test_recordBindSuccess_outside_warning_window_returns_null(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(changedAt: $this->minutesAgo(10)),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    expireWarning: 600,
                ),
            ),
        );

        self::assertNull($result->outcome->timeBeforeExpiration);
    }

    public function test_recordBindSuccess_must_change_propagates_error_code(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(mustChange: true),
            new PasswordPolicy(
                change: new PasswordChangeRules(mustChange: true),
            ),
        );

        self::assertFalse($result->outcome->denied);
        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $result->outcome->errorCode,
        );
    }

    /**
     * draft-behera-11 §7.2 needs both flags, so clearing pwdMustChange releases an entry still marked pwdReset.
     */
    public function test_recordBindSuccess_ignores_pwd_reset_when_the_policy_does_not_require_a_change(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(mustChange: true),
            new PasswordPolicy(),
        );

        self::assertNull($result->outcome->errorCode);
    }

    public function test_evaluatePasswordChange_delegates_to_constraint_chain(): void
    {
        $deny = PasswordPolicyOutcome::deny(
            PwdPolicyError::PASSWORD_TOO_SHORT,
            ResultCode::CONSTRAINT_VIOLATION,
            'denied',
        );
        $engine = $this->engineWith($this->stubConstraint($deny));

        $outcome = $engine->evaluatePasswordChange($this->changeAttempt());

        self::assertSame(
            $deny,
            $outcome,
        );
    }

    public function test_evaluatePasswordChange_chain_null_returns_allow(): void
    {
        $outcome = $this
            ->engineWith($this->stubConstraint(null))
            ->evaluatePasswordChange($this->changeAttempt());

        self::assertFalse($outcome->denied);
    }

    public function test_evaluatePasswordChange_passes_attempt_through(): void
    {
        $state = new UserPasswordState();
        $policy = new PasswordPolicy();
        $constraint = new RecordingPasswordChangeConstraint();

        $given = $this->changeAttempt(
            state: $state,
            policy: $policy,
            oldPassword: 'oldpw',
            isSelf: false,
        );

        $this->engineWith($constraint)->evaluatePasswordChange($given);

        self::assertSame(
            [$given],
            $constraint->invocations,
        );
    }

    public function test_recordPasswordChange_stamps_changed_time(): void
    {
        $changes = $this->subject->recordPasswordChange(
            ['{BCRYPT}hashed'],
            new UserPasswordState(),
            new PasswordPolicy(),
        );

        $change = $this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
        );
        self::assertSame(
            [GeneralizedTime::format($this->clock->now())],
            $change->getAttribute()->getValues(),
        );
    }

    public function test_recordPasswordChange_zero_history_emits_no_history_change(): void
    {
        $changes = $this->subject->recordPasswordChange(
            ['{BCRYPT}hashed'],
            new UserPasswordState(),
            new PasswordPolicy(
                quality: new PasswordQualityRules(inHistory: 0),
            ),
        );

        self::assertNull($this->findChangeOrNull(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_HISTORY,
        ));
    }

    public function test_recordPasswordChange_prepends_and_trims_history(): void
    {
        $oldest = $this->historyEntry(
            $this->minutesAgo(180),
            '{BCRYPT}old1',
        );
        $newer = $this->historyEntry(
            $this->minutesAgo(60),
            '{BCRYPT}old2',
        );

        $changes = $this->subject->recordPasswordChange(
            ['{BCRYPT}replaced'],
            new UserPasswordState(history: [
                $newer,
                $oldest,
            ]),
            new PasswordPolicy(
                quality: new PasswordQualityRules(inHistory: 2),
            ),
        );

        $historyChange = $this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_HISTORY,
        );
        $values = $historyChange->getAttribute()->getValues();
        self::assertCount(
            2,
            $values,
        );
        self::assertStringContainsString(
            '{BCRYPT}replaced',
            $values[0],
        );
        self::assertStringContainsString(
            '{BCRYPT}old2',
            $values[1],
        );
    }

    public function test_recordPasswordChange_clears_must_change_failure_and_lock(): void
    {
        $changes = $this->subject->recordPasswordChange(
            ['{BCRYPT}hashed'],
            new UserPasswordState(
                accountLockedAt: $this->minutesAgo(5),
                failureTimes: [$this->minutesAgo(2)],
                graceUseTimes: [$this->minutesAgo(1)],
                mustChange: true,
            ),
            new PasswordPolicy(),
        );

        self::assertTrue($this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_RESET,
        )->isReset());
        self::assertTrue($this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
        )->isReset());
        self::assertTrue($this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        )->isReset());
        self::assertTrue($this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME,
        )->isReset());
    }

    public function test_recordPasswordChange_clean_state_emits_only_changed_time(): void
    {
        $changes = $this->subject->recordPasswordChange(
            ['{BCRYPT}hashed'],
            new UserPasswordState(),
            new PasswordPolicy(
                quality: new PasswordQualityRules(inHistory: 0),
            ),
        );

        self::assertCount(
            1,
            $changes->changes,
        );
        self::assertSame(
            PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
            $changes->changes[0]->getAttribute()->getName(),
        );
    }

    public function test_record_forwarded_state_unions_failures_and_derives_lockout(): void
    {
        $existing = $this->clock->now()->modify('-1 minute');
        $forwarded = $this->clock->now();
        $changes = $this->subject->recordForwardedState(
            new UserPasswordState(failureTimes: [$existing]),
            new PasswordPolicy(lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: 2,
            )),
            [$forwarded],
            null,
        );

        $byAttribute = $this->changesByAttribute($changes);

        self::assertCount(
            2,
            $byAttribute['pwdFailureTime'],
        );
        self::assertNotSame(
            [],
            $byAttribute['pwdAccountLockedTime'],
        );
    }

    public function test_record_forwarded_state_dedups_a_resent_value(): void
    {
        $existing = $this->clock->now()->modify('-1 minute');
        $changes = $this->subject->recordForwardedState(
            new UserPasswordState(failureTimes: [$existing]),
            new PasswordPolicy(lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: 3,
            )),
            [$existing],
            null,
        );

        $byAttribute = $this->changesByAttribute($changes);

        self::assertCount(
            1,
            $byAttribute['pwdFailureTime'],
        );
        self::assertArrayNotHasKey(
            'pwdAccountLockedTime',
            $byAttribute,
        );
    }

    public function test_a_forwarded_success_clears_the_failures_it_supersedes(): void
    {
        $beforeSuccess = $this->clock->now()->modify('-2 minutes');
        $success = $this->clock->now()->modify('-1 minute');
        $changes = $this->subject->recordForwardedState(
            new UserPasswordState(failureTimes: [$beforeSuccess]),
            new PasswordPolicy(lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: 2,
            )),
            [],
            $success,
        );

        $byAttribute = $this->changesByAttribute($changes);

        self::assertSame(
            [],
            $byAttribute['pwdFailureTime'],
        );
        self::assertSame(
            [$success->format('YmdHis') . 'Z'],
            $byAttribute['pwdLastSuccess'],
        );
    }

    public function test_a_forwarded_success_keeps_later_failures_locked(): void
    {
        $beforeSuccess = $this->clock->now()->modify('-2 minutes');
        $success = $this->clock->now()->modify('-1 minute');
        $afterSuccess = $this->clock->now();
        $changes = $this->subject->recordForwardedState(
            new UserPasswordState(failureTimes: [$beforeSuccess]),
            new PasswordPolicy(lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: 1,
            )),
            [$afterSuccess],
            $success,
        );

        $byAttribute = $this->changesByAttribute($changes);

        self::assertCount(
            1,
            $byAttribute['pwdFailureTime'],
        );
        self::assertNotSame(
            [],
            $byAttribute['pwdAccountLockedTime'],
        );
    }

    public function test_a_forwarded_success_clears_a_failure_driven_lock(): void
    {
        $beforeSuccess = $this->clock->now()->modify('-2 minutes');
        $success = $this->clock->now()->modify('-1 minute');
        $changes = $this->subject->recordForwardedState(
            new UserPasswordState(
                accountLockedAt: $this->clock->now()->modify('-90 seconds'),
                failureTimes: [$beforeSuccess],
            ),
            new PasswordPolicy(lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: 2,
            )),
            [],
            $success,
        );

        $byAttribute = $this->changesByAttribute($changes);

        self::assertSame(
            [],
            $byAttribute['pwdFailureTime'],
        );
        self::assertSame(
            [],
            $byAttribute['pwdAccountLockedTime'],
        );
    }

    public function test_a_permanent_lock_is_never_cleared_by_a_forward(): void
    {
        $changes = $this->subject->recordForwardedState(
            new UserPasswordState(
                accountLockedAt: $this->clock->now(),
                permanentlyLocked: true,
                failureTimes: [$this->clock->now()],
            ),
            new PasswordPolicy(lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: 2,
            )),
            [],
            $this->clock->now(),
        );

        self::assertTrue($changes->isEmpty());
    }

    private function changeAttempt(
        ?UserPasswordState $state = null,
        ?PasswordPolicy $policy = null,
        ?string $oldPassword = null,
        bool $isSelf = true,
    ): PasswordChangeAttempt {
        return new PasswordChangeAttempt(
            newPassword: 'newpw',
            oldPassword: $oldPassword,
            state: $state ?? new UserPasswordState(),
            policy: $policy ?? new PasswordPolicy(),
            isSelf: $isSelf,
        );
    }

    private function engineWith(PasswordChangeConstraint $constraint): PasswordPolicyEngine
    {
        return new PasswordPolicyEngine(
            clock: $this->clock,
            changeConstraints: new PasswordChangeConstraintChain([$constraint]),
            uniqueTimes: $this->uniqueTimes,
        );
    }

    private function minutesAgo(int $minutes): DateTimeImmutable
    {
        return $this->clock
            ->now()
            ->sub(new DateInterval(sprintf('PT%dM', $minutes)));
    }

    /**
     * @param list<Change> $changes
     */
    private function findChange(
        array $changes,
        string $name,
    ): Change {
        $found = $this->findChangeOrNull(
            $changes,
            $name,
        );
        self::assertNotNull(
            $found,
            sprintf('Expected change for "%s" in operational changes.', $name),
        );

        return $found;
    }

    /**
     * @param list<Change> $changes
     */
    private function findChangeOrNull(
        array $changes,
        string $name,
    ): ?Change {
        foreach ($changes as $change) {
            if (strcasecmp($change->getAttribute()->getName(), $name) === 0) {
                return $change;
            }
        }

        return null;
    }

    private function historyEntry(
        DateTimeImmutable $when,
        string $stored,
    ): HistoryEntry {
        return HistoryEntry::forStoredPassword(
            $when->setTimezone(new DateTimeZone('UTC')),
            $stored,
        );
    }

    /**
     * @return array<string, string[]>
     */
    private function changesByAttribute(OperationalChanges $changes): array
    {
        $byAttribute = [];

        foreach ($changes->changes as $change) {
            $byAttribute[$change->getAttribute()->getName()] = $change->getAttribute()->getValues();
        }

        return $byAttribute;
    }

    private function stubConstraint(?PasswordPolicyOutcome $outcome): PasswordChangeConstraint
    {
        $stub = $this->createMock(PasswordChangeConstraint::class);
        $stub
            ->method('check')
            ->willReturn($outcome);

        return $stub;
    }
}
