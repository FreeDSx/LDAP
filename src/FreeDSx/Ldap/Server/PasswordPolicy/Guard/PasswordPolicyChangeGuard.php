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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Guard;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\PasswordPolicyException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordModifyAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Enforces password policy on a password change, returning deltas to persist alongside it.
 */
final readonly class PasswordPolicyChangeGuard
{
    public function __construct(
        private PasswordPolicyEngine $engine,
        private PasswordPolicyResolver $resolver,
        private PasswordPolicyContext $context,
        private EventLogger $eventLogger,
        private PasswordHashService $hashService = new PasswordHashService(),
    ) {}

    /**
     * @throws OperationException|PasswordPolicyException when the new password violates the governing policy.
     */
    public function enforce(PasswordModifyAttempt $attempt): OperationalChanges
    {
        return $this->enforceAll([$attempt]);
    }

    /**
     * Validate every new value of a multi-valued password set against the same target and return the combined deltas.
     *
     * @param non-empty-list<PasswordModifyAttempt> $attempts one per new password value being set
     * @throws OperationException|PasswordPolicyException when any new value violates the governing policy.
     */
    public function enforceAll(array $attempts): OperationalChanges
    {
        $primary = $attempts[0];
        $policy = $this->resolver->resolveFor($primary->target);
        if ($policy === null) {
            return OperationalChanges::none();
        }

        $state = UserPasswordState::fromEntry($primary->target);
        // The values being replaced serve both §8.2.6's current-password check and §8.2.7's history rotation.
        // An entry created by this same operation holds the new values, not superseded ones.
        $replaced = $primary->isNewEntry
            ? []
            : array_values($primary->target->get($policy->pwdAttribute)?->getValues() ?? []);

        foreach ($attempts as $attempt) {
            $outcome = $this->engine->evaluatePasswordChange(new PasswordChangeAttempt(
                newPassword: $attempt->newPassword,
                oldPassword: $attempt->oldPassword,
                state: $state,
                policy: $policy,
                isSelf: $attempt->isSelf,
                passwordIsCleartext: $attempt->passwordIsCleartext,
                currentPasswords: $replaced,
            ));
            if ($outcome->denied) {
                $this->reject(
                    $outcome,
                    $attempt,
                );
            }
        }

        $this->assertSafeModifyCredential(
            $policy,
            $primary,
        );

        return $this->engine->recordPasswordChange(
            $replaced,
            $state,
            $policy,
            $primary->isSelf,
        );
    }

    /**
     * Verifies the supplied existing password under pwdSafeModify; presence is already enforced by the constraint chain.
     *
     * @throws OperationException when an existing password is supplied but does not match the stored value.
     */
    private function assertSafeModifyCredential(
        PasswordPolicy $policy,
        PasswordModifyAttempt $attempt,
    ): void {
        $oldPassword = $attempt->oldPassword;
        if (!$attempt->isSelf || $policy->change->safeModify !== true || $oldPassword === null || $oldPassword === '') {
            return;
        }

        foreach ($attempt->target->get($policy->pwdAttribute)?->getValues() ?? [] as $stored) {
            if ($this->hashService->verify($oldPassword, $stored)) {
                return;
            }
        }

        $this->reject(
            new PasswordPolicyOutcome(
                denied: true,
                ldapResultCode: ResultCode::INVALID_CREDENTIALS,
                diagnostic: 'The supplied existing password is incorrect.',
            ),
            $attempt,
        );
    }

    /**
     * @throws OperationException
     */
    private function reject(
        PasswordPolicyOutcome $outcome,
        PasswordModifyAttempt $attempt,
    ): never {
        $this->context->setOutcome($outcome);
        $this->eventLogger->record(
            ServerEvent::PasswordPolicyChangeRejected,
            [EventContext::TARGET => [EventContext::DN => $attempt->target->getDn()->toString()]],
        );

        throw new OperationException(
            $outcome->diagnostic,
            $outcome->ldapResultCode,
        );
    }
}
