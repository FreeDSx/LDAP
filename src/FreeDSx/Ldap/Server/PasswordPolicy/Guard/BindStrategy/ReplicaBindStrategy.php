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

use DateTimeImmutable;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
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

        // Local state is read before the entry: applying a replicated entry drops the state it supersedes.
        $local = $this->store->load($attempt->uuid);
        $current = $this->currentState($attempt);

        if ($local->isRecordedAgainst(self::versionOf($current, $attempt))) {
            $localOutcome = $this->engine->evaluateLocalLockout(
                $local->toUserPasswordState($attempt->dn),
                $attempt->policy,
            );

            if ($localOutcome->denied) {
                return $localOutcome;
            }
        }

        return $current === null
            ? PasswordPolicyOutcome::allow()
            : $this->engine->evaluatePreBind(
                $current,
                $attempt->policy,
            );
    }

    public function record(
        PasswordBindAttempt $attempt,
        callable $decide,
    ): RecordedOutcome {
        $recorded = null;

        $this->store->atomicMutate(
            $attempt->uuid,
            self::versionOf(
                $this->currentState($attempt),
                $attempt,
            ),
            function (ReplicaPasswordState $local) use ($attempt, $decide, &$recorded): OperationalChanges {
                $recorded = $decide($this->combine(
                    $attempt->state,
                    $local,
                    $attempt->dn,
                ));

                return $recorded->changes;
            },
        );

        // Nothing is merged when the entry is gone or the write was dropped, and the bind still gets its decision.
        return $recorded ?? $decide($this->combine(
            $attempt->state,
            ReplicaPasswordState::empty(),
            $attempt->dn,
        ))->unstored();
    }

    /**
     * The entry's policy state as it stands now, or null when the entry is gone.
     */
    private function currentState(PasswordBindAttempt $attempt): ?UserPasswordState
    {
        $entry = $this->backend->get(
            $attempt->dn,
            self::stateProjection(),
        );

        // Another entry now at the DN is not the one being bound; the bound one counts as gone.
        if ($entry === null || $entry->getUuid() !== strtolower($attempt->uuid)) {
            return null;
        }

        return UserPasswordState::fromEntry($entry);
    }

    /**
     * Only the policy state and identity, without the linked values a large group would otherwise load.
     */
    private static function stateProjection(): EntryProjection
    {
        return new EntryProjection(
            array_map(
                Attribute::normalizeName(...),
                [
                    ...UserPasswordState::ATTRIBUTES,
                    AttributeTypeOid::NAME_ENTRY_UUID,
                ],
            ),
            0,
        );
    }

    /**
     * The password the entry holds now, or the one the attempt read when the entry is gone.
     */
    private static function versionOf(
        ?UserPasswordState $current,
        PasswordBindAttempt $attempt,
    ): ?DateTimeImmutable {
        return $current === null
            ? $attempt->state->changedAt
            : $current->changedAt;
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
