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

namespace FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;

/**
 * Applies sync results from an upstream provider to a local replica.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChangeApplierInterface
{
    /**
     * Reset present-set tracking at the start of a new sync's refresh phase.
     */
    public function beginRefresh(): void;

    /**
     * Apply one sync result: add and modify are upserts, delete is a removal.
     *
     * During the refresh phase the entry's DN is recorded so {@see self::reconcile()} can find local entries the
     * upstream no longer has.
     */
    public function apply(
        SyncEntryResult $result,
        Session $session,
    ): void;

    /**
     * Apply one bulk UUID set: a delete set removes each entry, a present set marks them seen for reconciliation.
     *
     * @return list<Dn> the DNs the set removed, which only a UUID lookup against storage can resolve
     */
    public function applyIdSet(
        SyncIdSetResult $result,
        Session $session,
    ): array;

    /**
     * Delete local entries not seen during a present-phase refresh (reconcile by absence).
     *
     * Only safe after a refresh where {@see Session::hasRefreshDeletes()} is false; an incremental refresh conveys its
     * deletes explicitly and must not be reconciled this way.
     */
    public function reconcile(): void;
}
