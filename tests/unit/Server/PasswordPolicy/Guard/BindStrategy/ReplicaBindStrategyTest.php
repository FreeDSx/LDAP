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
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
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
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
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

    private ReplicaPasswordStateStoreInterface $store;

    private LdapBackendInterface&MockObject $backend;

    private PasswordPolicyContext $context;

    private RecordingSleeper $sleeper;

    private PasswordPolicyBindGuard $subject;

    protected function setUp(): void
    {
        // Both resolve from the memoised container, so the state store shares the storage holding the subject.
        $this->fromContainer(EntryStorageInterface::class)
            ->store(new Entry(
                new Dn(self::DN),
                new Attribute('cn', 'foo'),
            ));
        $this->store = $this->fromContainer(ReplicaPasswordStateStoreInterface::class);
        $this->backend = $this->createMock(LdapBackendInterface::class);
        $this->context = new PasswordPolicyContext();
        $this->sleeper = new RecordingSleeper();

        $engine = new PasswordPolicyEngine(
            clock: FrozenClock::fromString(self::NOW),
            changeConstraints: new PasswordChangeConstraintChain([]),
        );
        $this->subject = new PasswordPolicyBindGuard(
            $engine,
            new ReplicaBindStrategy(
                $engine,
                $this->store,
                $this->backend,
            ),
            $this->context,
            new EventLogger(
                new RecordingLogger(),
                EventLogPolicy::all(),
            ),
            $this->sleeper,
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
                new Attribute('pwdAccountLockedTime', '20260520120000Z'),
            ));

        $this->expectException(OperationException::class);

        $this->subject->preBind($this->attempt(new UserPasswordState()));
    }

    public function test_preBind_allows_when_neither_the_local_state_nor_the_entry_locks(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(new Entry(new Dn(self::DN)));

        $this->expectNotToPerformAssertions();

        $this->subject->preBind($this->attempt(new UserPasswordState()));
    }

    public function test_failure_is_persisted_to_the_local_store(): void
    {
        $this->subject->recordFailure($this->attempt(
            new UserPasswordState(),
            $this->lockoutPolicy(3),
        ));

        self::assertFalse(
            $this->store->load(new Dn(self::DN))->isEmpty(),
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

    private function localState(): UserPasswordState
    {
        return $this->store
            ->load(new Dn(self::DN))
            ->toUserPasswordState(new Dn(self::DN));
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
