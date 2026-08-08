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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\DnBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\SaslBindPolicyEnforcer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\EntryBindStrategy;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Storage\BackendFactoryTrait;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class SaslBindPolicyEnforcerTest extends TestCase
{
    use BackendFactoryTrait;

    private const NOW = '2026-05-20T12:00:00Z';

    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private FrozenClock $clock;

    private WritableStorageBackend $backend;

    private PasswordPolicyContext $context;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString(self::NOW);
        $this->context = new PasswordPolicyContext();
        $this->context->setResponseRequested(true);
    }

    public function test_without_a_policy_it_does_nothing(): void
    {
        $enforcer = $this->enforcer(null);

        $enforcer->recordFailure(self::USER_DN);
        $enforcer->enforceSuccess(
            self::USER_DN,
            new Dn(self::USER_DN),
        );

        self::assertNull($this->context->getOutcome());
        self::assertNull($this->context->buildResponseControl());
        self::assertFalse($enforcer->mustChangePassword());
    }

    public function test_null_username_failure_is_ignored(): void
    {
        $this->enforcer($this->lockoutPolicy())->recordFailure(null);

        self::assertNull($this->context->getOutcome());
    }

    public function test_failure_is_recorded_through_the_guard(): void
    {
        $this->enforcer($this->lockoutPolicy())->recordFailure(self::USER_DN);

        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $this->context->getOutcome()?->errorCode,
        );
        self::assertNotNull(
            $this->backend
                ->get(new Dn(self::USER_DN))
                ?->get(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME),
        );
    }

    public function test_locked_account_is_denied_on_success(): void
    {
        $enforcer = $this->enforcer(
            $this->lockoutPolicy(),
            [PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME => PasswordPolicyOid::PERMANENT_LOCK_SENTINEL],
        );

        try {
            $enforcer->enforceSuccess(
                self::USER_DN,
                new Dn(self::USER_DN),
            );
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
    }

    public function test_must_change_flags_the_context_and_surfaces_a_control(): void
    {
        $enforcer = $this->enforcer(
            new PasswordPolicy(),
            [PasswordPolicyOid::NAME_PWD_RESET => 'TRUE'],
        );

        $enforcer->enforceSuccess(
            self::USER_DN,
            new Dn(self::USER_DN),
        );

        self::assertTrue($enforcer->mustChangePassword());

        $control = $this->context->buildResponseControl();
        self::assertInstanceOf(
            PwdPolicyResponseControl::class,
            $control,
        );
        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $control->getError(),
        );
    }

    public function test_clean_success_carries_no_control(): void
    {
        $enforcer = $this->enforcer(new PasswordPolicy());

        $enforcer->enforceSuccess(
            self::USER_DN,
            new Dn(self::USER_DN),
        );

        self::assertNull($this->context->buildResponseControl());
        self::assertFalse($enforcer->mustChangePassword());
    }

    /**
     * @param array<string, string> $userAttrs
     */
    private function enforcer(
        ?PasswordPolicy $policy,
        array $userAttrs = [],
    ): SaslBindPolicyEnforcer {
        $this->backend = self::makeWritableBackend(new InMemoryStorage([
            Entry::fromArray(
                'dc=foo,dc=bar',
                [
                    'objectClass' => ['domain'],
                    'dc' => ['foo'],
                ],
            ),
            Entry::fromArray(
                self::USER_DN,
                [
                    'objectClass' => ['inetOrgPerson'],
                    'cn' => ['user'],
                    'sn' => ['User'],
                    'userPassword' => ['12345'],
                ] + $userAttrs,
            ),
        ]));

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
            new EventLogger(null, EventLogPolicy::all()),
            new BlockingSleeper(),
        );

        return new SaslBindPolicyEnforcer(
            new DnBindNameResolver(),
            $this->backend,
            new PasswordPolicyResolver(
                $this->backend,
                null,
                $policy,
            ),
            $guard,
            $this->context,
        );
    }

    private function lockoutPolicy(): PasswordPolicy
    {
        return new PasswordPolicy(
            lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: 1,
            ),
        );
    }
}
