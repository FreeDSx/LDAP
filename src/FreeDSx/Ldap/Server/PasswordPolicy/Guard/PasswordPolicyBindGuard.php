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

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordBindAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\RecordedOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\PasswordPolicyBindStrategyInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Applies the engine's bind-time decisions against the state supplied by the configured bind strategy.
 */
final readonly class PasswordPolicyBindGuard
{
    public function __construct(
        private PasswordPolicyEngine $engine,
        private PasswordPolicyBindStrategyInterface $strategy,
        private PasswordPolicyContext $context,
        private EventLogger $eventLogger,
        private SleeperInterface $sleeper,
    ) {}

    /**
     * @throws OperationException when the account is locked and may not yet attempt a bind.
     */
    public function preBind(PasswordBindAttempt $attempt): void
    {
        $outcome = $this->strategy->preBindOutcome($attempt);
        if (!$outcome->denied) {
            return;
        }

        $this->context->setOutcome($outcome);
        $this->eventLogger->record(
            ServerEvent::PasswordPolicyAccountLocked,
            $this->subjectFor($attempt),
        );

        throw new OperationException(
            $outcome->diagnostic,
            $outcome->ldapResultCode,
        );
    }

    /**
     * Applies the same delay a real account earns, so a bind against a name that does not exist is not measurably
     * faster than one against a name that does.
     */
    public function delayUnknownIdentity(?PasswordPolicy $policy): void
    {
        if ($policy === null) {
            return;
        }

        $this->sleeper->sleep($this->engine->initialFailureDelay($policy));
    }

    /**
     * Records a failed bind but never throws (the caller re-throws the credential error), then applies the response delay.
     */
    public function recordFailure(PasswordBindAttempt $attempt): void
    {
        $recorded = $this->strategy->record(
            $attempt,
            fn(UserPasswordState $state): RecordedOutcome => $this->engine->recordBindFailure(
                $state,
                $attempt->policy,
            ),
        );

        if ($recorded->outcome->denied) {
            $this->context->setOutcome($recorded->outcome);
            $this->eventLogger->record(
                ServerEvent::PasswordPolicyAccountLocked,
                $this->subjectFor($attempt),
            );
        }

        $this->sleeper->sleep($recorded->delaySeconds);
    }

    /**
     * @throws OperationException when the password is expired with no grace logins remaining.
     */
    public function recordSuccess(PasswordBindAttempt $attempt): void
    {
        $state = null;
        $recorded = $this->strategy->record(
            $attempt,
            function (UserPasswordState $current) use ($attempt, &$state): RecordedOutcome {
                $state = $current;

                return $this->engine->recordBindSuccess(
                    $current,
                    $attempt->policy,
                );
            },
        );
        $outcome = $recorded->outcome;

        if ($outcome->denied) {
            $this->context->setOutcome($outcome);
            $this->eventLogger->record(
                ServerEvent::PasswordPolicyExpired,
                $this->subjectFor($attempt),
            );

            throw new OperationException(
                $outcome->diagnostic,
                $outcome->ldapResultCode,
            );
        }

        $this->context->setOutcome($outcome);
        $this->emitSuccessEvents(
            $attempt,
            $state ?? $attempt->state,
            $outcome,
        );
    }

    private function emitSuccessEvents(
        PasswordBindAttempt $attempt,
        UserPasswordState $state,
        PasswordPolicyOutcome $outcome,
    ): void {
        $subject = $this->subjectFor($attempt);

        if ($state->isLocked() && !$state->permanentlyLocked) {
            $this->eventLogger->record(
                ServerEvent::PasswordPolicyAccountUnlocked,
                $subject,
            );
        }
        if ($outcome->graceRemaining !== null) {
            $this->eventLogger->record(
                ServerEvent::PasswordPolicyGraceLogin,
                $subject,
            );
        }
        if ($outcome->errorCode === PwdPolicyError::CHANGE_AFTER_RESET) {
            $this->eventLogger->record(
                ServerEvent::PasswordPolicyMustChange,
                $subject,
            );
        }
    }

    /**
     * @return array<string, string>
     */
    private function subjectFor(PasswordBindAttempt $attempt): array
    {
        return [
            EventContext::USERNAME => $attempt->name,
            EventContext::DN => $attempt->dn->toString(),
        ];
    }
}
