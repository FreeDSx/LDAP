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

use FreeDSx\Ldap\Exception\UnresolvedReplicaMovesException;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\ReplicationCheckpointInterface;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;
use Psr\Log\LoggerInterface;

/**
 * Applies what a sync sends in the order it arrives, holding each refresh's cookie back until the refresh is reconciled.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ReplicaConsumer
{
    private bool $refreshing = false;

    /**
     * The cookie held back until the refresh it belongs to has been reconciled.
     */
    private ?string $pendingCookie = null;

    /**
     * Set when replicated entries could not be placed, making the next sync reload the content.
     */
    private bool $reload = false;

    private bool $fullRefresh = false;

    public function __construct(
        private readonly ChangeApplierInterface $applier,
        private readonly ReplicationCheckpointInterface $checkpoint,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * The cookie the next sync starts from, which a pending reload clears first.
     */
    public function startingCookie(): ?string
    {
        // Cleared rather than skipped, as a restart part way through the reload must not resume from it either.
        if ($this->reload) {
            $this->checkpoint->clear();
            $this->reload = false;
        }

        return $this->checkpoint->read();
    }

    /**
     * Makes the next sync reload the content.
     */
    public function reloadNext(): void
    {
        $this->reload = true;
    }

    /**
     * Holds the cookie back until the refresh is reconciled (RFC 4533 §3.8).
     */
    public function startRefresh(?string $cookie): void
    {
        $this->refreshing = true;
        $this->pendingCookie = null;
        $this->fullRefresh = $cookie === null;
        $this->applier->beginRefresh();
    }

    /**
     * @throws UnresolvedReplicaMovesException unless a full refresh is under way
     */
    public function applyEntry(
        SyncEntryResult $result,
        Session $session,
    ): void {
        try {
            $this->applier->apply(
                $result,
                $session,
            );
        } catch (UnresolvedReplicaMovesException $e) {
            $this->logDuringFullRefresh(
                $e,
                'A replicated entry could not be placed during a full refresh; skipping it.',
            );
        }
    }

    public function applyIdSet(
        SyncIdSetResult $result,
        Session $session,
    ): void {
        $this->applier->applyIdSet(
            $result,
            $session,
        );
    }

    /**
     * Held back links are tied to entries once reconciling has placed them, then entries moved aside are checked.
     *
     * @throws UnresolvedReplicaMovesException when the refresh resumed from a cookie
     */
    public function reconcileRefresh(Session $session): void
    {
        if (!$session->hasRefreshDeletes()) {
            $this->reconcile();
        }

        $this->applier->completeRefresh();
        $this->settleRefresh();
        $this->flushCookie();
        $this->refreshing = false;
    }

    /**
     * Entries moved aside are checked before the checkpoint moves past them.
     *
     * @throws UnresolvedReplicaMovesException
     */
    public function persistCookie(?string $cookie): void
    {
        if ($cookie === null) {
            return;
        }

        if ($this->refreshing) {
            $this->pendingCookie = $cookie;

            return;
        }

        $this->applier->settle();
        $this->checkpoint->write($cookie);
    }

    /**
     * @throws UnresolvedReplicaMovesException when the refresh resumed from a cookie
     */
    private function reconcile(): void
    {
        try {
            $this->applier->reconcile();
        } catch (UnresolvedReplicaMovesException $e) {
            $this->logDuringFullRefresh(
                $e,
                'Replicated entries a full refresh carried elsewhere could not be moved back; leaving them where they are.',
            );
        }
    }

    /**
     * @throws UnresolvedReplicaMovesException when the refresh resumed from a cookie
     */
    private function settleRefresh(): void
    {
        try {
            $this->applier->settle();
        } catch (UnresolvedReplicaMovesException $e) {
            $this->logDuringFullRefresh(
                $e,
                'Replicated entries moved aside were not placed again by a full refresh; leaving them where they are.',
            );
        }
    }

    /**
     * What a full refresh cannot place is logged rather than reloaded, as a reload would replay the same refresh.
     *
     * @throws UnresolvedReplicaMovesException unless a full refresh is under way
     */
    private function logDuringFullRefresh(
        UnresolvedReplicaMovesException $e,
        string $message,
    ): void {
        if (!$this->refreshing || !$this->fullRefresh) {
            throw $e;
        }

        $this->logger?->error(
            $message,
            ['dns' => $e->dns],
        );
    }

    private function flushCookie(): void
    {
        if ($this->pendingCookie === null) {
            return;
        }

        $this->checkpoint->write($this->pendingCookie);
        $this->pendingCookie = null;
    }
}
