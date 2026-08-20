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

namespace Tests\Integration\FreeDSx\Ldap\Security;

use DateInterval;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\DnBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordPolicyAwareAuthenticator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\EntryBindStrategy;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use Tests\Support\FreeDSx\Ldap\Server\Clock\RecordingSleeper;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordExpirationRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

/**
 * In-process integration of the real bind-enforcement stack against a writable backend.
 */
final class PasswordPolicyBindEnforcementTest extends TestCase
{
    use ServerContainerTrait;

    private const NOW = '2026-05-20T12:00:00Z';

    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private const PASSWORD = '12345';

    private FrozenClock $clock;

    private WritableStorageBackend $backend;

    private PasswordPolicyContext $context;

    private RecordingLogger $logger;

    private RecordingSleeper $sleeper;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString(self::NOW);
        $this->context = new PasswordPolicyContext();
        $this->logger = new RecordingLogger();
        $this->sleeper = new RecordingSleeper();
    }

    /**
     * A name that resolves to nothing must not be measurably faster to refuse than one that exists.
     */
    public function test_an_unknown_identity_still_incurs_the_anti_guessing_delay(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user(),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                    minDelay: 2,
                    maxDelay: 8,
                ),
            ),
        );

        $this->attemptBind(
            $authenticator,
            'wrong',
            'cn=nobody,dc=foo,dc=bar',
        );

        self::assertSame(
            [2.0],
            $this->sleeper->durations,
        );
    }

    public function test_repeated_failures_lock_the_account(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user(),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 2,
                ),
            ),
        );

        $this->attemptBind(
            $authenticator,
            'wrong',
        );
        $this->attemptBind(
            $authenticator,
            'wrong',
        );

        self::assertNotNull(
            $this->storedValue(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME),
            'Account should be locked after reaching pwdMaxFailure.',
        );

        try {
            $authenticator->authenticate(
                self::USER_DN,
                self::PASSWORD,
            );
            self::fail('A locked account must reject even a correct password.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_CREDENTIALS,
                $e->getCode(),
            );
        }

        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $this->context->getOutcome()?->errorCode,
        );
        $this->assertEventRecorded(ServerEvent::PasswordPolicyAccountLocked);
    }

    public function test_lockout_retriggers_after_duration_elapses(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME => $this->minutesAgo(120),
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME => [
                    $this->minutesAgo(121),
                    $this->minutesAgo(120),
                ],
            ]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    duration: 3600,
                    maxFailure: 2,
                ),
            ),
        );

        // The duration has elapsed, so a failed bind is attempted and the stale lock is cleared rather than persisting.
        $this->attemptBind(
            $authenticator,
            'wrong',
        );
        self::assertNull(
            $this->storedValue(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME),
            'An elapsed lock must be cleared on the next failed bind, not left stale.',
        );

        // Fresh failures must be able to lock the account again.
        $this->attemptBind(
            $authenticator,
            'wrong',
        );
        self::assertNotNull(
            $this->storedValue(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME),
            'Reaching pwdMaxFailure again after an elapsed lock must re-lock the account.',
        );
    }

    public function test_elapsed_lockout_unlocks_on_success(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME => $this->minutesAgo(120),
            ]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    duration: 3600,
                ),
            ),
        );

        $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        self::assertNull(
            $this->storedValue(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME),
            'A successful bind past the lockout duration should clear the lock.',
        );
        $this->assertEventRecorded(ServerEvent::PasswordPolicyAccountUnlocked);
    }

    public function test_bind_within_expiry_warning_returns_seconds_remaining(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => $this->minutesAgo(50),
            ]),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    expireWarning: 1200,
                ),
            ),
        );

        $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        self::assertSame(
            600,
            $this->context->getOutcome()?->timeBeforeExpiration,
        );
    }

    public function test_expired_password_within_grace_warns_and_records_use(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => $this->minutesAgo(120),
            ]),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    graceAuthnLimit: 3,
                ),
            ),
        );

        $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        self::assertSame(
            2,
            $this->context->getOutcome()?->graceRemaining,
        );
        self::assertNotNull($this->storedValue(PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME));
        $this->assertEventRecorded(ServerEvent::PasswordPolicyGraceLogin);
    }

    public function test_expired_password_beyond_grace_is_denied(): void
    {
        $exhausted = [
            $this->minutesAgo(30),
            $this->minutesAgo(20),
            $this->minutesAgo(10),
        ];
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => $this->minutesAgo(120),
                PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME => $exhausted,
            ]),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    graceAuthnLimit: 3,
                ),
            ),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        try {
            $authenticator->authenticate(
                self::USER_DN,
                self::PASSWORD,
            );
        } finally {
            self::assertSame(
                PwdPolicyError::PASSWORD_EXPIRED,
                $this->context->getOutcome()?->errorCode,
            );
        }
    }

    public function test_grace_login_within_grace_expiry_window_is_allowed(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                // Expired ten minutes ago (maxAge 60m), still inside the 30m grace-expiry window.
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => $this->minutesAgo(70),
            ]),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    graceAuthnLimit: 3,
                    graceExpiry: 1800,
                ),
            ),
        );

        $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        self::assertSame(
            2,
            $this->context->getOutcome()?->graceRemaining,
        );
        self::assertNotNull($this->storedValue(PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME));
    }

    public function test_grace_login_past_grace_expiry_window_is_denied(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                // Expired sixty minutes ago, beyond the 30m grace-expiry window, despite grace remaining by count.
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => $this->minutesAgo(120),
            ]),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    graceAuthnLimit: 3,
                    graceExpiry: 1800,
                ),
            ),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        try {
            $authenticator->authenticate(
                self::USER_DN,
                self::PASSWORD,
            );
        } finally {
            self::assertSame(
                PwdPolicyError::PASSWORD_EXPIRED,
                $this->context->getOutcome()?->errorCode,
            );
        }
    }

    public function test_idle_account_beyond_pwd_max_idle_is_locked(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_LAST_SUCCESS => $this->minutesAgo(120),
            ]),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(maxIdle: 3600),
            ),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        try {
            $authenticator->authenticate(
                self::USER_DN,
                self::PASSWORD,
            );
        } finally {
            self::assertSame(
                PwdPolicyError::ACCOUNT_LOCKED,
                $this->context->getOutcome()?->errorCode,
            );
        }
    }

    /**
     * draft-behera-11 §7.1 counts idleness from pwdLastSuccess, so a password change does not refresh it.
     */
    public function test_a_recent_password_change_does_not_recover_an_idle_locked_account(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_LAST_SUCCESS => $this->minutesAgo(120),
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => $this->minutesAgo(1),
            ]),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(maxIdle: 3600),
            ),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        try {
            $authenticator->authenticate(
                self::USER_DN,
                self::PASSWORD,
            );
        } finally {
            self::assertSame(
                PwdPolicyError::ACCOUNT_LOCKED,
                $this->context->getOutcome()?->errorCode,
            );
        }
    }

    /**
     * §7.1 falls back to pwdChangedTime only when no successful bind has been recorded.
     */
    public function test_idle_falls_back_to_the_change_time_when_no_bind_was_recorded(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME => $this->minutesAgo(1),
            ]),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(maxIdle: 3600),
            ),
        );

        $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        self::assertNull($this->context->getOutcome()?->errorCode);
    }

    public function test_successful_bind_records_last_success(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user(),
            new PasswordPolicy(),
        );

        $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        self::assertSame(
            GeneralizedTime::format($this->clock->now()),
            $this->storedValue(PasswordPolicyOid::NAME_PWD_LAST_SUCCESS),
        );
    }

    public function test_bind_rejected_before_password_start_time(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_START_TIME => $this->minutesFromNow(10),
            ]),
            new PasswordPolicy(),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );
    }

    public function test_bind_rejected_after_password_end_time(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_END_TIME => $this->minutesAgo(10),
            ]),
            new PasswordPolicy(),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        try {
            $authenticator->authenticate(
                self::USER_DN,
                self::PASSWORD,
            );
        } finally {
            self::assertSame(
                PwdPolicyError::PASSWORD_EXPIRED,
                $this->context->getOutcome()?->errorCode,
            );
        }
    }

    public function test_pwd_reset_surfaces_change_after_reset(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_RESET => 'TRUE',
            ]),
            new PasswordPolicy(
                change: new PasswordChangeRules(mustChange: true),
            ),
        );

        $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $this->context->getOutcome()?->errorCode,
        );
        $this->assertEventRecorded(ServerEvent::PasswordPolicyMustChange);
    }

    /**
     * draft-behera-11 §7.2 needs both flags, so clearing pwdMustChange releases an entry still marked pwdReset.
     */
    public function test_pwd_reset_is_ignored_when_the_policy_does_not_require_a_change(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_RESET => 'TRUE',
            ]),
            new PasswordPolicy(),
        );

        $token = $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        self::assertFalse($token->mustChangePassword());
        self::assertNull($this->context->getOutcome()?->errorCode);
    }

    public function test_pwd_reset_marks_token_for_required_change(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user([
                PasswordPolicyOid::NAME_PWD_RESET => 'TRUE',
            ]),
            new PasswordPolicy(
                change: new PasswordChangeRules(mustChange: true),
            ),
        );

        $token = $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        self::assertTrue($token->mustChangePassword());
    }

    public function test_normal_bind_does_not_mark_token_for_required_change(): void
    {
        $authenticator = $this->authenticatorFor(
            $this->user(),
            new PasswordPolicy(),
        );

        $token = $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        self::assertFalse($token->mustChangePassword());
    }

    /**
     * @param array<string, string|list<string>> $extra
     */
    private function user(array $extra = []): Entry
    {
        return Entry::fromArray(
            self::USER_DN,
            [
                'objectClass' => ['inetOrgPerson'],
                'cn' => ['user'],
                'sn' => ['User'],
                'userPassword' => [self::PASSWORD],
            ] + $extra,
        );
    }

    private function authenticatorFor(
        Entry $user,
        PasswordPolicy $policy,
    ): PasswordPolicyAwareAuthenticator {
        $this->backend = $this->backendFor(new InMemoryStorage([
            Entry::fromArray(
                'dc=foo,dc=bar',
                [
                    'objectClass' => ['domain'],
                    'dc' => ['foo'],
                ],
            ),
            $user,
        ]));

        $nameResolver = new DnBindNameResolver();
        $engine = new PasswordPolicyEngine(
            clock: $this->clock,
            changeConstraints: new PasswordChangeConstraintChain([]),
        );
        $guard = new PasswordPolicyBindGuard(
            $engine,
            new EntryBindStrategy(
                $engine,
                $this->backend,
            ),
            $this->context,
            new EventLogger(
                $this->logger,
                EventLogPolicy::all(),
            ),
            $this->sleeper,
        );

        return new PasswordPolicyAwareAuthenticator(
            new PasswordAuthenticator(
                $nameResolver,
                $this->backend,
            ),
            $nameResolver,
            $this->backend,
            new PasswordPolicyResolver(
                $this->backend,
                null,
                $policy,
            ),
            $guard,
        );
    }

    private function attemptBind(
        PasswordPolicyAwareAuthenticator $authenticator,
        string $password,
        ?string $dn = null,
    ): void {
        try {
            $authenticator->authenticate(
                $dn ?? self::USER_DN,
                $password,
            );
        } catch (OperationException) {
            // Expected for the failure-path scenarios under test.
        }
    }

    private function minutesAgo(int $minutes): string
    {
        return GeneralizedTime::format(
            $this->clock
                ->now()
                ->sub(new DateInterval(sprintf('PT%dM', $minutes))),
        );
    }

    private function minutesFromNow(int $minutes): string
    {
        return GeneralizedTime::format(
            $this->clock
                ->now()
                ->add(new DateInterval(sprintf('PT%dM', $minutes))),
        );
    }

    private function storedValue(string $attribute): ?string
    {
        return $this->backend
            ->get(new Dn(self::USER_DN))
            ?->get($attribute)
            ?->firstValue();
    }

    private function assertEventRecorded(ServerEvent $event): void
    {
        $events = [];
        foreach ($this->logger->records as $record) {
            $recorded = $record['context']['event'] ?? null;
            if (is_string($recorded)) {
                $events[] = $recorded;
            }
        }

        self::assertContains(
            $event->value,
            $events,
        );
    }
}
