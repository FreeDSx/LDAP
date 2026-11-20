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

use FreeDSx\Ldap\Exception\CancelRequestException;
use FreeDSx\Ldap\Exception\UnresolvedReplicaMovesException;
use FreeDSx\Ldap\Server\Clock\Sleeper\BackoffSleeper;
use FreeDSx\Ldap\Server\Logging\ExceptionLogging;
use FreeDSx\Ldap\Server\Process\Signals\ShutdownSignalsInterface;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\ReplicationCheckpointInterface;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;
use FreeDSx\Ldap\Sync\SyncRepl;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Keeps a local replica in sync with an upstream primary over RFC 4533.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class LdapReplica
{
    public const TASK_NAME = 'replica-sync';

    private bool $stopping = false;

    private ?SyncRepl $activeSync = null;

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

    /**
     * @param ?ShutdownSignalsInterface $signals null when a host server owns SIGTERM and drives {@see stop()} instead
     */
    public function __construct(
        private readonly PrimaryConnectionFactory $connectionFactory,
        private readonly ChangeApplierInterface $applier,
        private readonly ReplicationCheckpointInterface $checkpoint,
        private readonly BackoffSleeper $backoff,
        private readonly ?ShutdownSignalsInterface $signals = null,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * Consume from the primary until a shutdown signal, reconnecting with bounded backoff on failure.
     */
    public function run(): void
    {
        $this->signals?->onShutdown($this->stop(...));
        $this->logger?->info('Starting replica synchronization.');

        while (!$this->stopping) {
            try {
                $this->sync();
                $this->backoff->reset();
            } catch (CancelRequestException) {
                // A shutdown was requested; listen() was cancelled cleanly by the entry handler.
            } catch (UnresolvedReplicaMovesException $e) {
                $this->reload = true;
                $this->logger?->warning(
                    'Replicated entries could not be placed; reloading the content from the primary.',
                    ['dns' => $e->dns],
                );
            } catch (Throwable $e) {
                if ($this->stopping) {
                    break;
                }

                $this->logger?->warning(
                    'Replica synchronization failed; reconnecting after backoff.',
                    ExceptionLogging::makeLogContext($e) + ['backoff_seconds' => $this->backoff->delay()],
                );
                $this->backoff->wait();
            }
        }

        $this->logger?->info('Replica synchronization stopped.');
    }

    /**
     * Stop the daemon and break any in-progress listen; safe to call from a signal handler or another coroutine.
     */
    public function stop(): void
    {
        $this->stopping = true;
        $this->activeSync?->disconnect();
    }

    private function sync(): void
    {
        // Cleared rather than skipped, as a restart part way through the reload must not resume from it either.
        if ($this->reload) {
            $this->checkpoint->clear();
            $this->reload = false;
        }
        $cookie = $this->checkpoint->read();

        $syncRepl = $this->connectionFactory->connectSyncRepl();
        $syncRepl
            ->useCookie($cookie)
            ->useCookieHandler($this->persistCookie(...))
            ->useIdSetHandler($this->applyIdSet(...))
            ->useRefreshDoneHandler($this->reconcileRefresh(...))
            ->useRefreshRequiredHandler($this->startRefresh(...));

        $this->activeSync = $syncRepl;

        try {
            $this->startRefresh($cookie);
            $syncRepl->listen($this->applyEntry(...));
        } finally {
            $this->activeSync = null;
        }
    }

    /**
     * Holds the cookie back until the refresh is reconciled (RFC 4533 §3.8).
     */
    private function startRefresh(?string $cookie): void
    {
        $this->refreshing = true;
        $this->pendingCookie = null;
        $this->fullRefresh = $cookie === null;
        $this->applier->beginRefresh();
    }

    private function applyEntry(
        SyncEntryResult $result,
        Session $session,
    ): void {
        if ($this->stopping) {
            throw new CancelRequestException();
        }

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

    private function applyIdSet(
        SyncIdSetResult $result,
        Session $session,
    ): void {
        if ($this->stopping) {
            throw new CancelRequestException();
        }

        $this->applier->applyIdSet(
            $result,
            $session,
        );
    }

    /**
     * Entries moved aside are checked after reconciling, which may have removed them.
     */
    private function reconcileRefresh(Session $session): void
    {
        if (!$session->hasRefreshDeletes()) {
            $this->reconcile();
        }

        $this->settleRefresh();
        $this->flushCookie();
        $this->refreshing = false;
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

    /**
     * Entries moved aside are checked before the checkpoint moves past them.
     */
    private function persistCookie(?string $cookie): void
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

    private function flushCookie(): void
    {
        if ($this->pendingCookie === null) {
            return;
        }

        $this->checkpoint->write($this->pendingCookie);
        $this->pendingCookie = null;
    }
}
