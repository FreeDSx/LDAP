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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Read;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;

/**
 * Read-only view over the journal: the seam the audit sink and RFC 4533 provider consume.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ChangeStream
{
    public function __construct(
        private ChangeJournalInterface $journal,
    ) {}

    /**
     * Records with seq greater than $afterSeq, optionally narrowed to a scope, in ascending seq order.
     *
     * @api
     *
     * @return iterable<ChangeRecord>
     */
    public function since(
        int $afterSeq = 0,
        ?ChangeScope $scope = null,
    ): iterable {
        foreach ($this->journal->read($afterSeq) as $record) {
            if ($scope === null || $this->touchesScope($record->change, $scope)) {
                yield $record;
            }
        }
    }

    /**
     * The highest seq currently in the journal; the high-water mark a consumer cookie advances to.
     *
     * @api
     */
    public function latestSeq(): int
    {
        return $this->journal->latestSeq();
    }

    /**
     * Whether an incremental sync from $afterSeq is safe, or the cookie lapsed past the trim horizon and the
     * consumer must fall back to a present-phase full refresh.
     *
     * @api
     */
    public function retainsSince(int $afterSeq): bool
    {
        return $this->journal->retainsSince($afterSeq);
    }

    /**
     * The origin replica a sync cookie should be stamped with.
     *
     * @api
     */
    public function origin(): ReplicaId
    {
        return $this->journal->origin();
    }

    /**
     * A move is judged at both ends, since one leaving the scope is only tellable from where it used to be.
     */
    private function touchesScope(
        PendingChange $change,
        ChangeScope $scope,
    ): bool {
        return $scope->contains($change->dn)
            || ($change->previousDn !== null && $scope->contains($change->previousDn));
    }
}
