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

namespace FreeDSx\Ldap\Server\PasswordPolicy;

use DateTimeImmutable;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\RecordedOutcome;

/**
 * Core decision / tracking engine for draft-behera-10 password policy.
 */
final readonly class PasswordPolicyEngine
{
    private UniquePolicyTimeFactory $uniqueTimes;

    public function __construct(
        private ClockInterface $clock,
        private PasswordChangeConstraintChain $changeConstraints,
        ?UniquePolicyTimeFactory $uniqueTimes = null,
    ) {
        // The Container injects the configured factory; the fallback reuses this engine's clock so tests stay in sync.
        $this->uniqueTimes = $uniqueTimes
            ?? new UniquePolicyTimeFactory($this->clock, ReplicaId::local());
    }

    /**
     * Lockout check applied before the inner authenticator verifies credentials.
     */
    public function evaluatePreBind(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): PasswordPolicyOutcome {
        return $this->evaluateValidityWindow($state)
            ?? $this->evaluateIdleLockout($state, $policy)
            ?? ($this->isLockoutEffective($state, $policy)
                ? self::denyLocked()
                : PasswordPolicyOutcome::allow());
    }

    /**
     * Failure-driven lockout check only, for replica-local state that carries no primary-owned validity/idle policy.
     */
    public function evaluateLocalLockout(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): PasswordPolicyOutcome {
        return $this->isLockoutEffective($state, $policy)
            ? self::denyLocked()
            : PasswordPolicyOutcome::allow();
    }

    /**
     * Record a failed bind: append the current time to pwdFailureTime, and trip the lockout if the retained failure count meets pwdMaxFailure.
     *
     * Note: pwdFailureTime accumulates regardless of pwdLockout. Only the lock transition requires pwdLockout=TRUE (draft-behera-10 §5.2.9, §5.3.2).
     */
    public function recordBindFailure(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): RecordedOutcome {
        $now = $this->clock->now();
        $expired = $this->hasExpiredLock($state, $policy);
        $priorFailures = $expired ? [] : $state->failureTimes;

        $retained = $this->trimFailuresToInterval(
            $priorFailures,
            $policy,
        );
        $retained[] = $this->uniqueTimes->next($retained);

        $changes = [Change::replace(
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
            ...self::formatTimes($retained),
        )];

        $outcome = PasswordPolicyOutcome::allow();

        if ($this->shouldTripLockout($state, $policy, $retained)) {
            $changes[] = Change::replace(
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                GeneralizedTime::format($now),
            );
            $outcome = self::denyLocked();
        } elseif ($expired) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME);
        }

        return new RecordedOutcome(
            $outcome,
            OperationalChanges::of(...$changes),
            $this->bindFailureDelay($policy, count($retained)),
        );
    }

    /**
     * May deny if the password is expired and no grace remains; otherwise clears failures / lockout and surfaces any
     * warning (expiration, grace, reset).
     */
    public function recordBindSuccess(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): RecordedOutcome {
        $now = $this->clock->now();
        $secondsRemaining = $this->secondsUntilExpiration(
            $state,
            $policy,
        );
        $isExpired = $secondsRemaining !== null && $secondsRemaining <= 0;

        if ($isExpired && !$this->graceAvailable($state, $policy, $secondsRemaining)) {
            return new RecordedOutcome(
                PasswordPolicyOutcome::deny(
                    PwdPolicyError::PASSWORD_EXPIRED,
                    ResultCode::INVALID_CREDENTIALS,
                    'Password has expired.',
                ),
                OperationalChanges::none(),
            );
        }

        $changes = $this->buildSuccessChanges(
            $state,
            $now,
            $isExpired,
        );
        $outcome = $this->composeSuccessOutcome(
            $state,
            $policy,
            $secondsRemaining,
            $isExpired,
        );

        return new RecordedOutcome(
            $outcome,
            OperationalChanges::of(...$changes),
        );
    }

    /**
     * Merge a replica's forwarded bind state: union the failure times, drop any the observed success supersedes, and
     * re-derive lockout authoritatively.
     *
     * Additive by construction: forwarded failures only ever push toward locked, and a stale success can only clear
     * failures at or before its instant. Permanent (administrative) locks are never cleared by a forward.
     *
     * @param list<DateTimeImmutable> $forwardedFailures
     */
    public function recordForwardedState(
        UserPasswordState $state,
        PasswordPolicy $policy,
        array $forwardedFailures,
        ?DateTimeImmutable $lastSuccess,
    ): OperationalChanges {
        if ($state->permanentlyLocked) {
            return OperationalChanges::none();
        }

        $observedSuccess = $this->latestOf(
            $state->lastSuccess,
            $lastSuccess,
        );
        $prior = $this->hasExpiredLock($state, $policy)
            ? []
            : $state->failureTimes;
        $retained = $this->trimFailuresToInterval(
            $this->afterSuccess(
                $this->unionTimes($prior, $forwardedFailures),
                $observedSuccess,
            ),
            $policy,
        );

        $changes = [Change::replace(
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
            ...self::formatTimes($retained),
        )];

        $changes = $this->appendForwardedLockChange(
            $changes,
            $state,
            $policy,
            $retained,
        );
        if ($lastSuccess !== null && ($state->lastSuccess === null || $lastSuccess > $state->lastSuccess)) {
            $changes[] = Change::replace(
                PasswordPolicyOid::NAME_PWD_LAST_SUCCESS,
                GeneralizedTime::format($lastSuccess),
            );
        }

        return OperationalChanges::of(...$changes);
    }

    /**
     * Evaluate a password change against the configured constraint chain.
     */
    public function evaluatePasswordChange(PasswordChangeAttempt $attempt): PasswordPolicyOutcome
    {
        return $this->changeConstraints->evaluate($attempt)
            ?? PasswordPolicyOutcome::allow();
    }

    /**
     * Stamp pwdChangedTime, rotate pwdHistory, set/clear pwdReset, and clear pwdFailureTime / pwdAccountLockedTime /
     * pwdGraceUseTime.
     *
     * @param list<string> $replacedPasswords stored values the entry held before this change, empty when it held none
     */
    public function recordPasswordChange(
        array $replacedPasswords,
        UserPasswordState $state,
        PasswordPolicy $policy,
        bool $isSelf = true,
    ): OperationalChanges {
        $now = $this->clock->now();
        $changes = [Change::replace(
            PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
            GeneralizedTime::format($now),
        )];

        $historyChange = $this->buildHistoryChange(
            $replacedPasswords,
            $state,
            $policy,
            $now,
        );
        if ($historyChange !== null) {
            $changes[] = $historyChange;
        }

        $resetChange = $this->buildResetChange(
            $state,
            $policy,
            $isSelf,
        );
        if ($resetChange !== null) {
            $changes[] = $resetChange;
        }
        if ($state->failureTimes !== []) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_FAILURE_TIME);
        }
        if ($state->isLocked()) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME);
        }
        if ($state->graceUseTimes !== []) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME);
        }

        return OperationalChanges::of(...$changes);
    }

    /**
     * The delay a first failure earns, for a bind name that resolves to no entry and so has no failure count.
     */
    public function initialFailureDelay(PasswordPolicy $policy): float
    {
        return $this->bindFailureDelay(
            $policy,
            1,
        );
    }

    /**
     * Union two failure-time lists, deduplicating by generalized-time value so a re-sent forward is idempotent.
     *
     * @param list<DateTimeImmutable> $current
     * @param list<DateTimeImmutable> $forwarded
     * @return list<DateTimeImmutable>
     */
    private function unionTimes(
        array $current,
        array $forwarded,
    ): array {
        $byValue = [];

        foreach ([...$current, ...$forwarded] as $time) {
            $byValue[GeneralizedTime::formatWithFraction($time)] = $time;
        }

        return array_values($byValue);
    }

    /**
     * Drop failures a successful bind at the given instant supersedes; a boundary-equal failure is kept (fail-safe).
     *
     * @param list<DateTimeImmutable> $failures
     * @return list<DateTimeImmutable>
     */
    private function afterSuccess(
        array $failures,
        ?DateTimeImmutable $success,
    ): array {
        if ($success === null) {
            return $failures;
        }

        return array_values(array_filter(
            $failures,
            static fn(DateTimeImmutable $t): bool => $t >= $success,
        ));
    }

    /**
     * Set a fresh failure-driven lock when the retained failures newly meet the threshold, or clear a failure-driven
     * lock the retained failures no longer justify.
     *
     * @param list<Change> $changes
     * @param list<DateTimeImmutable> $retained
     * @return list<Change>
     */
    private function appendForwardedLockChange(
        array $changes,
        UserPasswordState $state,
        PasswordPolicy $policy,
        array $retained,
    ): array {
        $meetsThreshold = $this->meetsLockoutThreshold($policy, $retained);

        if ($meetsThreshold && !$this->isLockoutEffective($state, $policy)) {
            $changes[] = Change::replace(
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                GeneralizedTime::format($this->clock->now()),
            );
        } elseif (!$meetsThreshold && $state->accountLockedAt !== null) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME);
        }

        return $changes;
    }

    /**
     * Whether the retained failures reach pwdMaxFailure under an enabled lockout policy.
     *
     * @param list<DateTimeImmutable> $retained
     */
    private function meetsLockoutThreshold(
        PasswordPolicy $policy,
        array $retained,
    ): bool {
        return match (true) {
            $policy->lockout->enabled !== true,
            $policy->lockout->maxFailure === null,
            $policy->lockout->maxFailure === 0 => false,
            default => count($retained) >= $policy->lockout->maxFailure,
        };
    }

    /**
     * Lock an account that has had no successful bind within pwdMaxIdle seconds (draft-behera-10 §5.2.19, §5.3.x).
     */
    private function evaluateIdleLockout(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): ?PasswordPolicyOutcome {
        $maxIdle = $policy->expiration->maxIdle;
        // draft-behera-11 §7.1 counts from the last successful bind, falling back to the change time only when
        // no bind has been recorded, so a password change does not itself refresh idleness.
        $since = $state->lastSuccess ?? $state->changedAt;
        if ($maxIdle === null || $maxIdle === 0 || $since === null) {
            return null;
        }

        $idleSeconds = $this->clock->now()->getTimestamp() - $since->getTimestamp();
        if ($idleSeconds < $maxIdle) {
            return null;
        }

        return PasswordPolicyOutcome::deny(
            PwdPolicyError::ACCOUNT_LOCKED,
            ResultCode::INVALID_CREDENTIALS,
            'Account is locked due to inactivity.',
        );
    }

    /**
     * Reject a bind outside the pwdStartTime / pwdEndTime validity window (draft-behera-10 §5.3.8-5.3.9).
     */
    private function evaluateValidityWindow(UserPasswordState $state): ?PasswordPolicyOutcome
    {
        $now = $this->clock->now();

        if ($state->startTime !== null && $now < $state->startTime) {
            return new PasswordPolicyOutcome(
                denied: true,
                ldapResultCode: ResultCode::INVALID_CREDENTIALS,
                diagnostic: 'Password is not yet valid.',
            );
        }
        // draft-behera-11 §7.1 locks at the instant pwdEndTime is reached, not the second after it.
        if ($state->endTime !== null && $now >= $state->endTime) {
            return PasswordPolicyOutcome::deny(
                PwdPolicyError::PASSWORD_EXPIRED,
                ResultCode::INVALID_CREDENTIALS,
                'Password is no longer valid.',
            );
        }

        return null;
    }

    /**
     * Whether the account is currently locked: permanently, or within an unexpired pwdLockoutDuration window.
     */
    private function isLockoutEffective(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): bool {
        if ($state->permanentlyLocked) {
            return true;
        }
        if ($state->accountLockedAt === null) {
            return false;
        }

        $duration = $policy->lockout->duration;
        if ($duration === null || $duration === 0) {
            return true;
        }

        return $this->secondsSinceLock($state) < $duration;
    }

    /**
     * A timed lock whose pwdLockoutDuration has elapsed (such a lock must be cleared so failure counting restarts).
     */
    private function hasExpiredLock(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): bool {
        return $state->accountLockedAt !== null
            && !$state->permanentlyLocked
            && !$this->isLockoutEffective($state, $policy);
    }

    /**
     * @param list<DateTimeImmutable> $failures
     * @return list<DateTimeImmutable>
     */
    private function trimFailuresToInterval(
        array $failures,
        PasswordPolicy $policy,
    ): array {
        $interval = $policy->lockout->failureCountInterval;
        if ($interval === null || $interval === 0) {
            return $failures;
        }

        $nowTs = $this->clock->now()->getTimestamp();

        return array_values(array_filter(
            $failures,
            static fn(DateTimeImmutable $t): bool => ($nowTs - $t->getTimestamp()) < $interval,
        ));
    }

    /**
     * @param list<DateTimeImmutable> $retained
     */
    private function shouldTripLockout(
        UserPasswordState $state,
        PasswordPolicy $policy,
        array $retained,
    ): bool {
        return match (true) {
            $policy->lockout->enabled !== true,
            $policy->lockout->maxFailure === null,
            $policy->lockout->maxFailure === 0,
            $this->isLockoutEffective($state, $policy) => false,
            default => count($retained) >= $policy->lockout->maxFailure,
        };
    }

    /**
     * Response delay after a failed bind (draft-behera-10 §5.2.11-5.2.12): starts at pwdMinDelay and doubles per
     * consecutive failure, capped at pwdMaxDelay. Disabled unless both delays are positive.
     */
    private function bindFailureDelay(
        PasswordPolicy $policy,
        int $failureCount,
    ): float {
        $minDelay = $policy->lockout->minDelay ?? 0;
        $maxDelay = $policy->lockout->maxDelay ?? 0;

        if ($minDelay <= 0 || $maxDelay <= 0 || $failureCount < 1) {
            return 0.0;
        }

        // Cap the exponent so the doubling cannot overflow before the maxDelay clamp applies.
        $doublings = min($failureCount - 1, 30);

        return (float) min(
            $minDelay * (2 ** $doublings),
            $maxDelay,
        );
    }

    /**
     * Seconds remaining until pwdChangedTime + pwdMaxAge; null when expiration isn't configured or pwdChangedTime is
     * missing.
     *
     * Note: negative means already expired.
     */
    private function secondsUntilExpiration(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): ?int {
        $maxAge = $policy->expiration->maxAge;
        if ($maxAge === null || $maxAge === 0 || $state->changedAt === null) {
            return null;
        }

        $age = $this->clock->now()->getTimestamp()
            - $state->changedAt->getTimestamp();

        return $maxAge - $age;
    }

    /**
     * Number of grace logins still available. 0 means none left (or no grace configured).
     */
    private function graceRemaining(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): int {
        $limit = $policy->expiration->graceAuthnLimit;
        if ($limit === null || $limit === 0) {
            return 0;
        }

        return max(
            0,
            $limit - count($state->graceUseTimes),
        );
    }

    /**
     * Whether an expired password may still authenticate via a grace login: by count, and within pwdGraceExpiry if set.
     */
    private function graceAvailable(
        UserPasswordState $state,
        PasswordPolicy $policy,
        ?int $secondsRemaining,
    ): bool {
        if ($this->graceRemaining($state, $policy) === 0) {
            return false;
        }

        $window = $policy->expiration->graceExpiry;
        if ($window === null || $window === 0) {
            return true;
        }

        $secondsSinceExpiry = $secondsRemaining === null ? 0 : -$secondsRemaining;

        return $secondsSinceExpiry <= $window;
    }

    /**
     * @return list<Change>
     */
    private function buildSuccessChanges(
        UserPasswordState $state,
        DateTimeImmutable $now,
        bool $isExpired,
    ): array {
        $changes = [Change::replace(
            PasswordPolicyOid::NAME_PWD_LAST_SUCCESS,
            GeneralizedTime::format($now),
        )];

        if ($state->failureTimes !== []) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_FAILURE_TIME);
        }
        if ($state->accountLockedAt !== null && !$state->permanentlyLocked) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME);
        }
        if ($isExpired) {
            $graceTimes = [...$state->graceUseTimes, $this->uniqueTimes->next($state->graceUseTimes)];
            $changes[] = Change::replace(
                PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME,
                ...self::formatTimes($graceTimes),
            );
        }

        return $changes;
    }

    private function composeSuccessOutcome(
        UserPasswordState $state,
        PasswordPolicy $policy,
        ?int $secondsRemaining,
        bool $isExpired,
    ): PasswordPolicyOutcome {
        $errorCode = $state->mustChangeUnder($policy) ? PwdPolicyError::CHANGE_AFTER_RESET : null;
        $graceWarning = $isExpired
            ? $this->graceRemaining($state, $policy) - 1
            : null;
        $expirationWarning = $isExpired
            ? null
            : $this->expirationWarningSeconds($secondsRemaining, $policy);

        return new PasswordPolicyOutcome(
            denied: false,
            errorCode: $errorCode,
            timeBeforeExpiration: $expirationWarning,
            graceRemaining: $graceWarning,
        );
    }

    private function expirationWarningSeconds(
        ?int $secondsRemaining,
        PasswordPolicy $policy,
    ): ?int {
        $window = $policy->expiration->expireWarning;
        if ($secondsRemaining === null || $window === null || $window === 0) {
            return null;
        }
        if ($secondsRemaining > $window) {
            return null;
        }

        return $secondsRemaining;
    }

    /**
     * An administrative reset under pwdMustChange sets pwdReset; otherwise a prior pwdReset is satisfied and cleared.
     */
    private function buildResetChange(
        UserPasswordState $state,
        PasswordPolicy $policy,
        bool $isSelf,
    ): ?Change {
        if (!$isSelf && $policy->change->mustChange === true) {
            return Change::replace(
                PasswordPolicyOid::NAME_PWD_RESET,
                'TRUE',
            );
        }
        if ($state->mustChange) {
            return Change::reset(PasswordPolicyOid::NAME_PWD_RESET);
        }

        return null;
    }

    /**
     * draft-behera-11 §8.2.7 retains the password being replaced, not the one being set, so the window holds
     * pwdInHistory superseded values alongside the current one.
     *
     * @param list<string> $replacedPasswords
     */
    private function buildHistoryChange(
        array $replacedPasswords,
        UserPasswordState $state,
        PasswordPolicy $policy,
        DateTimeImmutable $now,
    ): ?Change {
        $depth = $policy->quality->inHistory;
        if ($depth === null || $depth === 0) {
            return null;
        }

        $newest = array_map(
            static fn(string $hash): HistoryEntry => HistoryEntry::forStoredPassword(
                $now,
                $hash,
            ),
            $replacedPasswords,
        );
        $retained = array_slice(
            [...$newest, ...$state->history],
            0,
            $depth,
        );

        return Change::replace(
            PasswordPolicyOid::NAME_PWD_HISTORY,
            ...array_map(
                static fn(HistoryEntry $entry): string => $entry->encode(),
                $retained,
            ),
        );
    }

    private function latestOf(
        ?DateTimeImmutable $a,
        ?DateTimeImmutable $b,
    ): ?DateTimeImmutable {
        if ($a === null || $b === null) {
            return $a ?? $b;
        }

        return max(
            $a,
            $b,
        );
    }

    private function secondsSinceLock(UserPasswordState $state): int
    {
        if ($state->accountLockedAt === null) {
            return 0;
        }

        return $this->clock->now()->getTimestamp()
            - $state->accountLockedAt->getTimestamp();
    }

    /**
     * @param list<DateTimeImmutable> $instants
     * @return list<string>
     */
    private static function formatTimes(array $instants): array
    {
        return array_values(array_map(
            static fn(DateTimeImmutable $t): string => GeneralizedTime::formatWithFraction($t),
            $instants,
        ));
    }

    private static function denyLocked(): PasswordPolicyOutcome
    {
        return PasswordPolicyOutcome::deny(
            PwdPolicyError::ACCOUNT_LOCKED,
            ResultCode::INVALID_CREDENTIALS,
            'Account is locked.',
        );
    }
}
