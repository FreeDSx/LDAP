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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordBindAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\ReplicaBindStrategy;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordExpirationRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\Server\Clock\RecordingSleeper;

final class ReplicaBindStrategyTest extends TestCase
{
    use ServerContainerTrait;

    private const NOW = '2026-05-20T12:00:00Z';

    private const DN = 'cn=foo,dc=example,dc=com';

    private const UUID = '6c5d4e3f-2a1b-4c0d-9e8f-7a6b5c4d3e2f';

    private const OTHER_UUID = '8a7b6c5d-4e3f-4a2b-9c1d-0e9f8a7b6c5d';

    private const MOVED_DN = 'cn=moved,dc=example,dc=com';

    private const PASSWORD_ONE = '20260101000000.250000Z';

    private const PASSWORD_TWO = '20260102000000.500000Z';

    private ReplicaPasswordStateStoreInterface $store;

    private ReadBackendInterface&MockObject $backend;

    private PasswordPolicyContext $context;

    private RecordingSleeper $sleeper;

    private PasswordPolicyBindGuard $subject;

    private PasswordPolicyBindGuard $storedEntrySubject;

    protected function setUp(): void
    {
        // Both resolve from the memoised container, so the state store shares the storage holding the subject.
        $this->fromContainer(WriteEntryInterface::class)
            ->store(new Entry(
                new Dn(self::DN),
                new Attribute('cn', 'foo'),
                new Attribute('entryUUID', self::UUID),
            ));
        $this->store = $this->fromContainer(ReplicaPasswordStateStoreInterface::class);
        $this->backend = $this->createMock(ReadBackendInterface::class);
        $this->context = new PasswordPolicyContext();
        $this->sleeper = new RecordingSleeper();

        $engine = new PasswordPolicyEngine(
            clock: FrozenClock::fromString(self::NOW),
            changeConstraints: new PasswordChangeConstraintChain([]),
        );
        $this->subject = $this->guardOver(
            $engine,
            $this->backend,
        );
        $this->storedEntrySubject = $this->guardOver(
            $engine,
            $this->fromContainer(ReadBackendInterface::class),
        );
    }

    public function test_local_failures_accumulate_and_lock_with_the_primary_never_writing(): void
    {
        $policy = $this->lockoutPolicy(2);

        $this->subject->recordFailure($this->attempt(new UserPasswordState(), $policy));
        $this->subject->recordFailure($this->attempt(new UserPasswordState(), $policy));

        self::assertTrue(
            $this->localState()->isLocked(),
            'The replica must lock locally once pwdMaxFailure is reached.',
        );

        try {
            $this->subject->preBind($this->attempt(new UserPasswordState(), $policy));
            self::fail('A locally locked account must be denied even with a clean replicated entry.');
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
    }

    public function test_preBind_denies_a_replicated_entry_lock_with_no_local_state(): void
    {
        $this->expectException(OperationException::class);

        $this->subject->preBind($this->attempt(new UserPasswordState(permanentlyLocked: true)));
    }

    public function test_preBind_denies_when_the_entry_locked_after_the_caller_read_it(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(new Entry(
                new Dn(self::DN),
                new Attribute(
                    'entryUUID',
                    self::UUID,
                ),
                new Attribute(
                    'pwdAccountLockedTime',
                    '20260520120000Z',
                ),
            ));

        $this->expectException(OperationException::class);

        $this->subject->preBind($this->attempt(new UserPasswordState()));
    }

    public function test_preBind_allows_when_neither_the_local_state_nor_the_entry_locks(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(new Entry(
                new Dn(self::DN),
                new Attribute(
                    'entryUUID',
                    self::UUID,
                ),
            ));

        $this->expectNotToPerformAssertions();

        $this->subject->preBind($this->attempt(new UserPasswordState()));
    }

    public function test_preBind_ignores_a_local_lock_recorded_against_a_password_the_entry_has_since_replaced(): void
    {
        $held = $this->entryWithPassword(self::PASSWORD_ONE);
        $this->serveHeld($held);
        $policy = $this->lockoutPolicy(2);
        $before = new UserPasswordState(changedAt: GeneralizedTime::parse(self::PASSWORD_ONE));

        $this->subject->recordFailure($this->attempt(
            $before,
            $policy,
        ));
        $this->subject->recordFailure($this->attempt(
            $before,
            $policy,
        ));
        self::assertTrue($this->localState()->isLocked());
        $held = $this->entryWithPassword(self::PASSWORD_TWO);

        $this->subject->preBind($this->attempt(
            $before,
            $policy,
        ));
    }

    public function test_a_success_whose_write_was_dropped_still_refuses_an_expired_password(): void
    {
        $held = $this->entryWithPassword(self::PASSWORD_TWO);
        $this->serveHeld($held);
        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(changedAt: GeneralizedTime::parse(self::PASSWORD_TWO)),
            $this->lockoutPolicy(3),
        ));
        $held = $this->entryWithPassword(self::PASSWORD_ONE);

        try {
            $this->subject->recordSuccess($this->attempt(
                new UserPasswordState(changedAt: GeneralizedTime::parse(self::PASSWORD_ONE)),
                new PasswordPolicy(expiration: new PasswordExpirationRules(
                    maxAge: 86400,
                    graceAuthnLimit: 0,
                )),
            ));
            self::fail('An expired password must be refused even when its state is not stored.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_CREDENTIALS,
                $e->getCode(),
            );
        }

        self::assertTrue($this->store->load(self::UUID)->isRecordedAgainst(GeneralizedTime::parse(self::PASSWORD_TWO)));
    }

    public function test_a_failure_whose_write_was_dropped_reports_no_lock(): void
    {
        $held = $this->entryWithPassword(self::PASSWORD_TWO);
        $this->serveHeld($held);
        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(changedAt: GeneralizedTime::parse(self::PASSWORD_TWO)),
            $this->lockoutPolicy(3),
        ));
        $held = $this->entryWithPassword(self::PASSWORD_ONE);

        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(changedAt: GeneralizedTime::parse(self::PASSWORD_ONE)),
            $this->lockoutPolicy(1),
        ));

        self::assertNull($this->context->getOutcome());
        self::assertFalse($this->localState()->isLocked());
    }

    public function test_a_failure_is_not_recorded_against_another_entry_now_at_the_dn(): void
    {
        $storage = $this->fromContainer(WriteEntryInterface::class);
        $storage->remove(new Dn(self::DN));
        $storage->store(new Entry(
            new Dn(self::MOVED_DN),
            new Attribute(
                'cn',
                'moved',
            ),
            new Attribute(
                'entryUUID',
                self::UUID,
            ),
            new Attribute(
                'pwdChangedTime',
                self::PASSWORD_ONE,
            ),
        ));
        $storage->store(new Entry(
            new Dn(self::DN),
            new Attribute(
                'cn',
                'foo',
            ),
            new Attribute(
                'entryUUID',
                self::OTHER_UUID,
            ),
            new Attribute(
                'pwdChangedTime',
                self::PASSWORD_TWO,
            ),
        ));

        $this->storedEntrySubject->recordFailure($this->attempt(
            new UserPasswordState(changedAt: GeneralizedTime::parse(self::PASSWORD_ONE)),
            $this->lockoutPolicy(3),
        ));

        self::assertTrue($this->store->load(self::UUID)->isRecordedAgainst(GeneralizedTime::parse(self::PASSWORD_ONE)));
    }

    public function test_a_failure_whose_write_was_dropped_still_delays_the_bind(): void
    {
        $held = $this->entryWithPassword(self::PASSWORD_TWO);
        $this->serveHeld($held);
        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(changedAt: GeneralizedTime::parse(self::PASSWORD_TWO)),
            $this->lockoutPolicy(3),
        ));
        $held = $this->entryWithPassword(self::PASSWORD_ONE);

        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(changedAt: GeneralizedTime::parse(self::PASSWORD_ONE)),
            new PasswordPolicy(lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: 3,
                minDelay: 2,
                maxDelay: 8,
            )),
        ));

        self::assertSame(
            [
                0.0,
                2.0,
            ],
            $this->sleeper->durations,
        );
        self::assertTrue($this->store->load(self::UUID)->isRecordedAgainst(GeneralizedTime::parse(self::PASSWORD_TWO)));
    }

    public function test_a_failure_is_recorded_against_the_version_the_stored_entry_holds(): void
    {
        $this->fromContainer(WriteEntryInterface::class)
            ->store(new Entry(
                new Dn(self::DN),
                new Attribute(
                    'cn',
                    'foo',
                ),
                new Attribute(
                    'entryUUID',
                    self::UUID,
                ),
                new Attribute(
                    'pwdChangedTime',
                    self::PASSWORD_TWO,
                ),
            ));

        $this->storedEntrySubject->recordFailure($this->attempt(
            new UserPasswordState(),
            $this->lockoutPolicy(3),
        ));

        self::assertTrue($this->store->load(self::UUID)->isRecordedAgainst(GeneralizedTime::parse(self::PASSWORD_TWO)));
    }

    public function test_a_failure_is_recorded_against_the_password_the_entry_holds_now(): void
    {
        $this->backend
            ->method('get')
            ->willReturn($this->entryWithPassword(self::PASSWORD_TWO));

        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(changedAt: GeneralizedTime::parse(self::PASSWORD_ONE)),
            $this->lockoutPolicy(3),
        ));

        self::assertTrue($this->store->load(self::UUID)->isRecordedAgainst(GeneralizedTime::parse(self::PASSWORD_TWO)));
    }

    public function test_failure_is_persisted_to_the_local_store(): void
    {
        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(),
            $this->lockoutPolicy(3),
        ));

        self::assertFalse(
            $this->store->load(self::UUID)->isEmpty(),
            'A replica-observed failure must be recorded to the local store.',
        );
    }

    public function test_success_clears_local_failures_and_stamps_last_success(): void
    {
        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(),
            $this->lockoutPolicy(3),
        ));

        $this->subject->recordSuccess($this->attempt(new UserPasswordState()));

        $local = $this->localState();
        self::assertSame(
            [],
            $local->failureTimes,
        );
        self::assertNotNull($local->lastSuccess);
    }

    public function test_below_threshold_failure_does_not_lock(): void
    {
        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(),
            $this->lockoutPolicy(3),
        ));

        self::assertFalse($this->localState()->isLocked());
        self::assertNull($this->context->getOutcome());
    }

    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::sqlite();
    }

    private function guardOver(
        PasswordPolicyEngine $engine,
        ReadBackendInterface $backend,
    ): PasswordPolicyBindGuard {
        return new PasswordPolicyBindGuard(
            $engine,
            new ReplicaBindStrategy(
                $engine,
                $this->store,
                $backend,
            ),
            $this->context,
            new EventLogger(
                new RecordingLogger(),
                EventLogPolicy::all(),
            ),
            $this->sleeper,
            reportAccountLock: true,
        );
    }

    /**
     * Serves whatever entry $held names when the strategy re-reads the subject.
     */
    private function serveHeld(Entry &$held): void
    {
        $this->backend
            ->method('get')
            ->willReturnCallback(static function () use (&$held): Entry {
                return $held;
            });
    }

    private function entryWithPassword(string $changedTime): Entry
    {
        return new Entry(
            new Dn(self::DN),
            new Attribute(
                'entryUUID',
                self::UUID,
            ),
            new Attribute(
                'pwdChangedTime',
                $changedTime,
            ),
        );
    }

    private function localState(): UserPasswordState
    {
        return $this->store
            ->load(self::UUID)
            ->toUserPasswordState(new Dn(self::DN));
    }

    private function attempt(
        UserPasswordState $state,
        PasswordPolicy $policy = new PasswordPolicy(),
    ): PasswordBindAttempt {
        return new PasswordBindAttempt(
            name: 'foo',
            dn: new Dn(self::DN),
            uuid: self::UUID,
            state: $state,
            policy: $policy,
        );
    }

    /**
     * @param int<0, max> $maxFailure
     */
    private function lockoutPolicy(int $maxFailure): PasswordPolicy
    {
        return new PasswordPolicy(
            lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: $maxFailure,
            ),
        );
    }
}
