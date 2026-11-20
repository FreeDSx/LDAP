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

    /**
     * @param ?ShutdownSignalsInterface $signals null when a host server owns SIGTERM and drives {@see stop()} instead
     */
    public function __construct(
        private readonly PrimaryConnectionFactory $connectionFactory,
        private readonly ReplicaConsumer $consumer,
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
                $this->consumer->reloadNext();
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
        $cookie = $this->consumer->startingCookie();

        $syncRepl = $this->connectionFactory->connectSyncRepl();
        $syncRepl
            ->useCookie($cookie)
            ->useCookieHandler($this->consumer->persistCookie(...))
            ->useIdSetHandler($this->applyIdSet(...))
            ->useRefreshDoneHandler($this->consumer->reconcileRefresh(...))
            ->useRefreshRequiredHandler($this->consumer->startRefresh(...));

        $this->activeSync = $syncRepl;

        try {
            $this->consumer->startRefresh($cookie);
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

        $this->consumer->applyEntry(
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

        $this->consumer->applyIdSet(
            $result,
            $session,
        );
    }
}
