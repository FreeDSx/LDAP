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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordBindAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\RecordedOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordState;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Evaluates the worst of the replicated entry state and the replica-local bind state, and records failures/successes
 * to the replica-local store on a read-only replica.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReplicaBindStrategy implements PasswordPolicyBindStrategyInterface
{
    public function __construct(
        private PasswordPolicyEngine $engine,
        private ReplicaPasswordStateStoreInterface $store,
        private ReadBackendInterface $backend,
    ) {}

    /**
     * Deny on the primary's entry decision (validity / idle / lock), otherwise on the replica-local failure lock.
     */
    public function preBindOutcome(PasswordBindAttempt $attempt): PasswordPolicyOutcome
    {
        $entryOutcome = $this->engine->evaluatePreBind(
            $attempt->state,
            $attempt->policy,
        );

        if ($entryOutcome->denied) {
            return $entryOutcome;
        }

        $localOutcome = $this->engine->evaluateLocalLockout(
            $this->store->load($attempt->dn)->toUserPasswordState($attempt->dn),
            $attempt->policy,
        );

        if ($localOutcome->denied) {
            return $localOutcome;
        }

        return $this->reReadEntryOutcome($attempt);
    }

    public function record(
        PasswordBindAttempt $attempt,
        callable $decide,
    ): RecordedOutcome {
        $recorded = null;

        $this->store->atomicMutate(
            $attempt->dn,
            function (ReplicaPasswordState $local) use ($attempt, $decide, &$recorded): OperationalChanges {
                $recorded = $decide($this->combine(
                    $attempt->state,
                    $local,
                    $attempt->dn,
                ));

                return $recorded->changes;
            },
        );

        return $recorded ?? new RecordedOutcome(
            PasswordPolicyOutcome::allow(),
            OperationalChanges::none(),
        );
    }

    /**
     * The caller's entry state was read before the local one, and applying a replicated entry drops the local state it
     * supersedes. Both reading clear therefore has to be confirmed against the entry as it stands now.
     */
    private function reReadEntryOutcome(PasswordBindAttempt $attempt): PasswordPolicyOutcome
    {
        $entry = $this->backend->get($attempt->dn);

        if ($entry === null) {
            return PasswordPolicyOutcome::allow();
        }

        return $this->engine->evaluatePreBind(
            UserPasswordState::fromEntry($entry),
            $attempt->policy,
        );
    }

    /**
     * Combine primary-authored entry fields (expiry / validity / must-change) with the replica-local volatile state so
     * the engine decides against the worst of both.
     */
    private function combine(
        UserPasswordState $entry,
        ReplicaPasswordState $localState,
        Dn $dn,
    ): UserPasswordState {
        $local = $localState->toUserPasswordState($dn);

        return new UserPasswordState(
            changedAt: $entry->changedAt,
            accountLockedAt: $local->accountLockedAt,
            permanentlyLocked: $local->permanentlyLocked,
            failureTimes: $local->failureTimes,
            graceUseTimes: $local->graceUseTimes,
            mustChange: $entry->mustChange,
            policySubentry: $entry->policySubentry,
            startTime: $entry->startTime,
            endTime: $entry->endTime,
            lastSuccess: $local->lastSuccess,
        );
    }
}
