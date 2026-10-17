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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;

/**
 * Append-only log of committed writes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChangeJournalInterface
{
    /**
     * Records one read returns unless asked for fewer.
     */
    public const DEFAULT_READ_LIMIT = 1000;

    /**
     * Append a change, allocating the next monotonic seq, and return the stamped record.
     */
    public function append(PendingChange $change): ChangeRecord;

    /**
     * Append changes in order, allocating consecutive seqs, and return the stamped records.
     *
     * @param list<PendingChange> $changes
     *
     * @return list<ChangeRecord>
     */
    public function appendAll(array $changes): array;

    /**
     * Records with seq greater than $afterSeq, through $throughSeq and at most $limit of them, in ascending seq order.
     *
     * @api
     *
     * @param ?int $throughSeq the highest seq to read, or null for no upper bound
     * @param positive-int $limit
     *
     * @return iterable<ChangeRecord>
     */
    public function read(
        int $afterSeq = 0,
        ?int $throughSeq = null,
        int $limit = self::DEFAULT_READ_LIMIT,
    ): iterable;

    /**
     * Highest allocated seq, or 0 when nothing has been appended.
     *
     * @api
     */
    public function latestSeq(): int;

    /**
     * Whether every record after $afterSeq is still retained, so an incremental sync from it cannot miss a
     * pruned change; false means the cookie lapsed past the trim horizon and the consumer needs a full refresh.
     *
     * @api
     */
    public function retainsSince(int $afterSeq): bool;

    /**
     * Drop records that fall outside the policy; returns how many were removed. seq keeps climbing.
     *
     * @api
     */
    public function prune(RetentionPolicy $policy): int;

    /**
     * The replica that authored this journal's records; the origin a sync cookie is stamped with.
     *
     * @api
     */
    public function origin(): ReplicaId;

    /**
     * Identifies the data this journal was built over.
     *
     * @api
     */
    public function generation(): string;

    /**
     * Whether appends are observable from a separate OS process.
     *
     * @api
     */
    public function sharesAcrossProcesses(): bool;
}
