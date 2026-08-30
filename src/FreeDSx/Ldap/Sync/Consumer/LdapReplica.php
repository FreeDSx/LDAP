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
use FreeDSx\Ldap\Server\Config\Replication\ConsumerConfig;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\CoroutineSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Logging\ExceptionLogging;
use FreeDSx\Ldap\Server\Process\Signals\PcntlShutdownSignals;
use FreeDSx\Ldap\Server\Process\Signals\ShutdownSignalsInterface;
use FreeDSx\Ldap\Server\Process\Signals\SwooleShutdownSignals;
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

    public function __construct(
        private readonly PrimaryConnectionFactory $connectionFactory,
        private readonly ChangeApplierInterface $applier,
        private readonly ReplicationCheckpointInterface $checkpoint,
        private readonly SleeperInterface $sleeper,
        private readonly ?ShutdownSignalsInterface $signals = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly ReconnectBackoff $backoff = new ReconnectBackoff(),
    ) {}

    public static function forPcntl(
        ConsumerConfig $config,
        EntryStorageInterface $storage,
        ?LoggerInterface $logger = null,
        ?PrimaryConnectionFactory $connectionFactory = null,
        ?ReplicaPasswordStateStoreInterface $passwordStateStore = null,
    ): self {
        return self::create(
            $config,
            $storage,
            new BlockingSleeper(),
            new PcntlShutdownSignals(),
            $logger,
            $connectionFactory,
            $passwordStateStore,
        );
    }

    /**
     * @param ?ShutdownSignalsInterface $signals null when a host server owns SIGTERM and drives {@see stop()} instead
     */
    public static function forSwoole(
        ConsumerConfig $config,
        EntryStorageInterface $storage,
        ?LoggerInterface $logger = null,
        ?ShutdownSignalsInterface $signals = new SwooleShutdownSignals(),
        ?PrimaryConnectionFactory $connectionFactory = null,
        ?ReplicaPasswordStateStoreInterface $passwordStateStore = null,
    ): self {
        return self::create(
            $config,
            $storage,
            new CoroutineSleeper(),
            $signals,
            $logger,
            $connectionFactory,
            $passwordStateStore,
        );
    }

    /**
     * Consume from the primary until a shutdown signal, reconnecting with bounded backoff on failure.
     */
    public function run(): void
    {
        $this->signals?->onShutdown($this->stop(...));
        $this->logger?->info('Starting replica synchronization.');

        $delay = $this->backoff->initial();

        while (!$this->stopping) {
            try {
                $this->sync();
                $delay = $this->backoff->initial();
            } catch (CancelRequestException) {
                // A shutdown was requested; listen() was cancelled cleanly by the entry handler.
            } catch (Throwable $e) {
                if ($this->stopping) {
                    break;
                }

                $this->logger?->warning(
                    'Replica synchronization failed; reconnecting after backoff.',
                    ExceptionLogging::makeLogContext($e) + ['backoff_seconds' => $delay],
                );
                $this->sleeper->sleep($delay);
                $delay = $this->backoff->next($delay);
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

    private static function create(
        ConsumerConfig $config,
        EntryStorageInterface $storage,
        SleeperInterface $sleeper,
        ?ShutdownSignalsInterface $signals,
        ?LoggerInterface $logger,
        ?PrimaryConnectionFactory $connectionFactory = null,
        ?ReplicaPasswordStateStoreInterface $passwordStateStore = null,
    ): self {
        // listen() must not time out its blocking read, or the persist phase would abort each interval.
        $config->getPrimary()
            ->setTimeoutRead(-1);

        $applier = new VerbatimStorageApplier($storage);

        return new self(
            connectionFactory: $connectionFactory ?? new PrimaryConnectionFactory($config),
            applier: $passwordStateStore !== null
                ? new ReconcilingChangeApplier($applier, $passwordStateStore)
                : $applier,
            checkpoint: $config->getCheckpoint(),
            sleeper: $sleeper,
            signals: $signals,
            logger: $logger,
            backoff: $config->getReconnectBackoff(),
        );
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
