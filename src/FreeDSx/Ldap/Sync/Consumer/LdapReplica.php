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
        $syncRepl = $this->connectionFactory->connectSyncRepl();
        $syncRepl
            ->useCookie($this->checkpoint->read())
            ->useCookieHandler($this->persistCookie(...))
            ->useIdSetHandler($this->applyIdSet(...))
            ->useRefreshDoneHandler($this->reconcileRefresh(...));

        $this->activeSync = $syncRepl;
        $this->refreshing = true;
        $this->pendingCookie = null;

        try {
            $this->applier->beginRefresh();
            $syncRepl->listen($this->applyEntry(...));
        } finally {
            $this->activeSync = null;
        }
    }

    private function applyEntry(
        SyncEntryResult $result,
        Session $session,
    ): void {
        if ($this->stopping) {
            throw new CancelRequestException();
        }

        $this->applier->apply(
            $result,
            $session,
        );
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

    private function reconcileRefresh(Session $session): void
    {
        if (!$session->hasRefreshDeletes()) {
            $this->applier->reconcile();
        }

        $this->flushCookie();
        $this->refreshing = false;
    }

    private function persistCookie(?string $cookie): void
    {
        if ($cookie === null) {
            return;
        }

        if ($this->refreshing) {
            $this->pendingCookie = $cookie;

            return;
        }

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
