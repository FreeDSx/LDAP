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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Replica;

use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Persists replica-observed password-policy bind state locally, keyed by each subject's lowercased entryUUID.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ReplicaPasswordStateStoreInterface
{
    /**
     * The locally tracked state for a subject, or an empty state when none has been recorded.
     */
    public function load(string $uuid): ReplicaPasswordState;

    /**
     * Atomically read the subject's current local state, derive changes from it via $merge, and apply them under an
     * exclusive lock so concurrent binds cannot lose an update; a state-changing apply advances the forward watermark.
     *
     * @param callable(ReplicaPasswordState): OperationalChanges $merge
     */
    public function atomicMutate(
        string $uuid,
        callable $merge,
    ): void;

    /**
     * Subjects whose local state has advanced past the last forwarded watermark, oldest first, capped at $limit.
     *
     * @return list<ReplicaForwardState>
     */
    public function listUnforwarded(int $limit = 100): array;

    /**
     * Advance a subject's forwarded watermark to $sequence, so state no newer than it is no longer pending forward.
     */
    public function markForwarded(
        string $uuid,
        int $sequence,
    ): void;

    /**
     * Drop a subject's local state when the replicated $authoritative entry supersedes it, so the entry becomes the
     * single source of truth. It's a no-op while the local state still enforces something the entry has not yet reflected.
     */
    public function discardIfSuperseded(
        string $uuid,
        UserPasswordState $authoritative,
    ): void;
}
