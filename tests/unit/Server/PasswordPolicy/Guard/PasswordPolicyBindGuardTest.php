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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\Guard;

use DateInterval;
use DateTimeImmutable;
use LogicException;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\RecordedOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\PasswordPolicyBindStrategyInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordBindAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordExpirationRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\Server\Clock\RecordingSleeper;

final class PasswordPolicyBindGuardTest extends TestCase
{
    private const NOW = '2026-05-20T12:00:00Z';

    private const DN = 'cn=foo,dc=example,dc=com';

    private FrozenClock $clock;

    private RecordingLogger $logger;

    private PasswordPolicyContext $context;

    private RecordingSleeper $sleeper;

    private PasswordPolicyEngine $engine;

    private OperationalChanges $recordedChanges;

    private PasswordPolicyBindGuard $subject;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString(self::NOW);
        $this->logger = new RecordingLogger();
        $this->context = new PasswordPolicyContext();
        $this->sleeper = new RecordingSleeper();
        $this->recordedChanges = OperationalChanges::none();
        $this->engine = new PasswordPolicyEngine(
            clock: $this->clock,
            changeConstraints: new PasswordChangeConstraintChain([]),
        );

        // Fake the strategy's persistence: run the engine decision against the attempt state and capture its changes,
        // so this test stays focused on the guard's orchestration (the atomic persistence is covered by strategy tests).
        $strategy = $this->createMock(PasswordPolicyBindStrategyInterface::class);
        $strategy->method('preBindOutcome')->willReturnCallback(
            fn(PasswordBindAttempt $attempt): PasswordPolicyOutcome => $this->engine->evaluatePreBind(
                $attempt->state,
                $attempt->policy,
            ),
        );
        $strategy->method('record')->willReturnCallback(
            function (PasswordBindAttempt $attempt, callable $decide): RecordedOutcome {
                $recorded = $decide($attempt->state);
                if (!$recorded instanceof RecordedOutcome) {
                    throw new LogicException('The decide callback must return a RecordedOutcome.');
                }
                $this->recordedChanges = $recorded->changes;

                return $recorded;
            },
        );

        $this->subject = new PasswordPolicyBindGuard(
            $this->engine,
            $strategy,
            $this->context,
            new EventLogger(
                $this->logger,
                EventLogPolicy::all(),
            ),
            $this->sleeper,
        );
    }

    public function test_preBind_allows_an_unlocked_account(): void
    {
        $this->subject->preBind($this->attempt(new UserPasswordState()));

        self::assertNull($this->context->getOutcome());
        self::assertTrue($this->recordedChanges->isEmpty());
    }

    public function test_preBind_denies_a_locked_account(): void
    {
        try {
            $this->subject->preBind($this->attempt(new UserPasswordState(permanentlyLocked: true)));
            self::fail('Expected an OperationException.');
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

    public function test_recordFailure_below_threshold_writes_without_locking(): void
    {
        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                ),
            ),
        ));

        self::assertNull($this->context->getOutcome());
        $this->assertWroteAttribute(PasswordPolicyOid::NAME_PWD_FAILURE_TIME);
        $this->assertNoEventRecorded(ServerEvent::PasswordPolicyAccountLocked);
    }

    public function test_recordFailure_trips_lockout_at_threshold(): void
    {
        $this->subject->recordFailure($this->attempt(
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
        ));

        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $this->context->getOutcome()?->errorCode,
        );
        $this->assertWroteAttribute(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME);
        $this->assertEventRecorded(ServerEvent::PasswordPolicyAccountLocked);
    }

    public function test_recordFailure_delays_the_response_by_the_configured_delay(): void
    {
        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    minDelay: 3,
                    maxDelay: 60,
                ),
            ),
        ));

        self::assertSame(
            [3.0],
            $this->sleeper->durations,
        );
    }

    public function test_recordFailure_requests_no_delay_when_unconfigured(): void
    {
        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                ),
            ),
        ));

        self::assertSame(
            [0.0],
            $this->sleeper->durations,
        );
    }

    public function test_recordSuccess_clean_state_stamps_last_success(): void
    {
        $this->subject->recordSuccess($this->attempt(new UserPasswordState()));

        self::assertFalse($this->context->getOutcome()?->denied);
        $this->assertWroteAttribute(PasswordPolicyOid::NAME_PWD_LAST_SUCCESS);
    }

    public function test_recordSuccess_expired_without_grace_denies(): void
    {
        try {
            $this->subject->recordSuccess($this->attempt(
                new UserPasswordState(changedAt: $this->minutesAgo(120)),
                new PasswordPolicy(
                    expiration: new PasswordExpirationRules(maxAge: 3600),
                ),
            ));
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_CREDENTIALS,
                $e->getCode(),
            );
        }

        self::assertSame(
            PwdPolicyError::PASSWORD_EXPIRED,
            $this->context->getOutcome()?->errorCode,
        );
        self::assertTrue($this->recordedChanges->isEmpty());
        $this->assertEventRecorded(ServerEvent::PasswordPolicyExpired);
    }

    public function test_recordSuccess_expired_within_grace_warns_and_records(): void
    {
        $this->subject->recordSuccess($this->attempt(
            new UserPasswordState(changedAt: $this->minutesAgo(120)),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    graceAuthnLimit: 3,
                ),
            ),
        ));

        self::assertSame(
            2,
            $this->context->getOutcome()?->graceRemaining,
        );
        $this->assertWroteAttribute(PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME);
        $this->assertEventRecorded(ServerEvent::PasswordPolicyGraceLogin);
    }

    public function test_recordSuccess_unlocks_a_previously_locked_account(): void
    {
        $this->subject->recordSuccess($this->attempt(
            new UserPasswordState(accountLockedAt: $this->minutesAgo(120)),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    duration: 3600,
                ),
            ),
        ));

        $this->assertWroteAttribute(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME);
        $this->assertEventRecorded(ServerEvent::PasswordPolicyAccountUnlocked);
    }

    public function test_recordSuccess_surfaces_must_change(): void
    {
        $this->subject->recordSuccess($this->attempt(
            new UserPasswordState(mustChange: true),
            new PasswordPolicy(
                change: new PasswordChangeRules(mustChange: true),
            ),
        ));

        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $this->context->getOutcome()?->errorCode,
        );
        $this->assertEventRecorded(ServerEvent::PasswordPolicyMustChange);
    }

    private function attempt(
        UserPasswordState $state,
        PasswordPolicy $policy = new PasswordPolicy(),
    ): PasswordBindAttempt {
        return new PasswordBindAttempt(
            name: 'foo',
            dn: new Dn(self::DN),
            state: $state,
            policy: $policy,
        );
    }

    private function minutesAgo(int $minutes): DateTimeImmutable
    {
        return $this->clock
            ->now()
            ->sub(new DateInterval(sprintf('PT%dM', $minutes)));
    }

    private function assertWroteAttribute(string $name): void
    {
        self::assertTrue(
            $this->wroteAttribute($name),
            sprintf('Expected a system write touching "%s".', $name),
        );
    }

    private function wroteAttribute(string $name): bool
    {
        foreach ($this->recordedChanges->changes as $change) {
            if (strcasecmp($change->getAttribute()->getName(), $name) === 0) {
                return true;
            }
        }

        return false;
    }

    private function assertEventRecorded(ServerEvent $event): void
    {
        self::assertContains(
            $event->value,
            $this->recordedEvents(),
        );
    }

    private function assertNoEventRecorded(ServerEvent $event): void
    {
        self::assertNotContains(
            $event->value,
            $this->recordedEvents(),
        );
    }

    /**
     * @return list<string>
     */
    private function recordedEvents(): array
    {
        $events = [];
        foreach ($this->logger->records as $record) {
            $event = $record['context']['event'] ?? null;
            if (is_string($event)) {
                $events[] = $event;
            }
        }

        return $events;
    }
}
