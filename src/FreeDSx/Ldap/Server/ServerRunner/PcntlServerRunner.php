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

namespace FreeDSx\Ldap\Server\ServerRunner;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotPublisher;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\Process\BackgroundTask\PcntlBackgroundTasks;
use FreeDSx\Ldap\Server\Process\ChildChannel;
use FreeDSx\Ldap\Server\Process\ChildProcess;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketServer;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use Closure;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Throwable;

/**
 * Uses PNCTL to fork incoming requests and send them to the server protocol handler.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PcntlServerRunner implements ServerRunnerInterface
{
    use ServerRunnerLoggerTrait;
    use ReloadsConfigurationTrait;

    /**
     * Child exit codes that tell the parent why a connection ended, so it can record the metric.
     */
    private const EXIT_CODE_WRITE_TIMEOUT = 10;

    private const EXIT_CODE_IDLE_TIMEOUT = 11;

    private const EXIT_CODE_REQUEST_SIZE_EXCEEDED = 12;

    private const EXIT_CODE_PROTOCOL_ERROR = 13;

    private SocketServer $server;

    /**
     * @var ChildProcess[]
     */
    private array $childProcesses = [];

    private bool $isMainProcess = true;

    /**
     * Used to guard against certain handlers only the owning PID should run.
     */
    private readonly int $ownerPid;

    /**
     * @var int[] These are the POSIX signals we handle for shutdown purposes.
     */
    private array $handledSignals = [];

    private bool $isShuttingDown = false;

    private readonly BackgroundTasksInterface $backgroundTasks;

    /**
     * @var array<string, mixed>
     */
    private array $defaultContext = [];

    /**
     * @throws RuntimeException
     */
    public function __construct(
        ServerProtocolFactoryInterface $serverProtocolFactory,
        ServerListenerOptionsInterface $options,
        private readonly SocketServerFactory $socketServerFactory,
        Closure $protocolFactoryProvider,
        private readonly MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
        private readonly ?SnapshotPublisher $snapshotPublisher = null,
        private readonly ?OperationRollupCoordinator $operationRollup = null,
        private readonly ?ResettableInterface $resettable = null,
        BackgroundTasksInterface $backgroundTasks = new PcntlBackgroundTasks(
            periodicTasks: [],
            longLivedTasks: [],
        ),
    ) {
        if (!extension_loaded('pcntl') || !extension_loaded('posix')) {
            throw new RuntimeException(
                'The pcntl and posix extensions are required to fork and manage child processes (Linux only).',
            );
        }

        $this->serverProtocolFactory = $serverProtocolFactory;
        $this->options = $options;
        $this->protocolFactoryProvider = $protocolFactoryProvider;

        // We need to be able to handle signals as they come in, regardless of what is going on...
        pcntl_async_signals(true);

        $this->handledSignals = [
            SIGINT,
            SIGTERM,
            SIGQUIT,
        ];
        $this->ownerPid = posix_getpid();
        $this->defaultContext = [
            'pid' => $this->ownerPid,
        ];

        $backgroundTasks->onChildStart($this->enterChild(...));
        $this->backgroundTasks = $backgroundTasks;
    }

    /**
     * @throws EncoderException
     */
    public function run(): void
    {
        $this->server = $this->socketServerFactory->makeAndBind();

        try {
            $this->acceptClients();
        } catch (Throwable $e) {
            $this->logAcceptError($e, $this->defaultContext);

            throw $e;
        } finally {
            if ($this->isMainProcess) {
                $this->handleServerShutdown();
            }
        }
    }

    /**
     * Check each child process we have and see if it is stopped. This will clean up zombie processes.
     */
    private function cleanUpChildProcesses(): void
    {
        foreach ($this->childProcesses as $index => $childProcess) {
            $status = 0;

            $result = pcntl_waitpid(
                $childProcess->getPid(),
                $status,
                WNOHANG,
            );

            if ($result === -1 || $result > 0) {
                unset($this->childProcesses[$index]);
                $this->drainOperationDelta($childProcess);
                $socket = $childProcess->getSocket();
                $this->server->removeClient($socket);
                $socket->close();
                $this->metricsRecorder->connectionObserved(ConnectionObservation::Closed);
                $this->recordChildCloseReason(
                    $result,
                    is_int($status) ? $status : 0,
                );
                $this->logInfo(
                    'The child process has ended.',
                    array_merge(
                        $this->defaultContext,
                        ['child_pid' => $childProcess->getPid()],
                    ),
                );

                continue;
            }

            // update cn=monitor with fresh stats.
            $this->collectOperationDelta($childProcess);
        }

        $this->publishMetricsSnapshot();
    }

    private function publishMetricsSnapshot(): void
    {
        $this->snapshotPublisher?->publish();
    }

    /**
     * Fold the operation deltas available on a live child's channel into the parent totals.
     */
    private function collectOperationDelta(ChildProcess $childProcess): void
    {
        $channel = $childProcess->getChannel();

        if ($channel === null || $this->operationRollup === null) {
            return;
        }

        $this->operationRollup->collect($channel);
    }

    /**
     * Fold a reaped child's final operation metrics into the parent totals, then close its channel.
     */
    private function drainOperationDelta(ChildProcess $childProcess): void
    {
        $this->collectOperationDelta($childProcess);
        $childProcess->getChannel()?->close();
    }

    /**
     * The exit code a child uses to tell the parent which close reason, if any, ended the connection.
     */
    private function childExitCodeFor(?ConnectionObservation $closeReason): int
    {
        return match ($closeReason) {
            ConnectionObservation::WriteTimeout => self::EXIT_CODE_WRITE_TIMEOUT,
            ConnectionObservation::IdleTimeout => self::EXIT_CODE_IDLE_TIMEOUT,
            ConnectionObservation::RequestSizeExceeded => self::EXIT_CODE_REQUEST_SIZE_EXCEEDED,
            ConnectionObservation::ProtocolError => self::EXIT_CODE_PROTOCOL_ERROR,
            default => 0,
        };
    }

    /**
     * Record a reaped child's close reason from its exit status, alongside the connection-closed gauge update.
     */
    private function recordChildCloseReason(
        int $result,
        int $status,
    ): void {
        if ($result <= 0 || !pcntl_wifexited($status)) {
            return;
        }

        $observation = match (pcntl_wexitstatus($status)) {
            self::EXIT_CODE_WRITE_TIMEOUT => ConnectionObservation::WriteTimeout,
            self::EXIT_CODE_IDLE_TIMEOUT => ConnectionObservation::IdleTimeout,
            self::EXIT_CODE_REQUEST_SIZE_EXCEEDED => ConnectionObservation::RequestSizeExceeded,
            self::EXIT_CODE_PROTOCOL_ERROR => ConnectionObservation::ProtocolError,
            default => null,
        };

        if ($observation !== null) {
            $this->metricsRecorder->connectionObserved($observation);
        }
    }

    /**
     * Accept clients from the socket server in a loop with a timeout. This lets us to periodically check existing
     * children processes as we listen for new ones.
     */
    private function acceptClients(): void
    {
        $this->installServerSignalHandlers();
        $this->logServerStarted($this->defaultContext);
        $this->metricsRecorder->serverStarted(time());
        $this->publishMetricsSnapshot();
        $this->options->getOnServerReady()?->__invoke();
        $this->backgroundTasks->start();

        do {
            $this->backgroundTasks->tick();
            $socket = $this->server->accept($this->options->getNetworkConfig()->getSocketAcceptTimeout());

            if ($this->isShuttingDown) {
                if ($socket) {
                    $this->logClientRejectedDuringShutdown($this->defaultContext);
                    $socket->close();
                }

                break;
            }

            // If there was no client received, we still want to clean up any children that have stopped.
            if ($socket === null) {
                $this->cleanUpChildProcesses();

                continue;
            }

            $maxConnections = $this->options->getNetworkConfig()->getMaxConnections();
            if ($maxConnections > 0 && count($this->childProcesses) >= $maxConnections) {
                $this->logConnectionLimitReached($this->defaultContext);
                $this->metricsRecorder->connectionObserved(ConnectionObservation::Rejected);
                $this->publishMetricsSnapshot();

                $this->server->removeClient($socket);
                $socket->close();

                continue;
            }

            $channel = $this->makeChildChannel();

            // A child inherits the parent's handlers. Block them until it has installed its own.
            $this->blockSignals();

            $pid = pcntl_fork();
            if ($pid == -1) {
                // In parent process, but could not fork...
                $this->unblockSignals();
                $channel?->close();
                $this->logAndThrow(
                    'Unable to fork process.',
                    $this->defaultContext,
                );
            } elseif ($pid === 0) {
                // This is the child's thread of execution...
                $this->runChildProcessThenExit(
                    $socket,
                    posix_getpid(),
                    $channel,
                );
            } else {
                // We are in the parent; the PID is the child process.
                $this->unblockSignals();
                $this->runAfterChildStarted(
                    $pid,
                    $socket,
                    $channel,
                );
            }
            // Use the shutdown flag, not the socket state (not reliable after forking)
        } while (!$this->isShuttingDown);
    }

    /**
     * Install signal handlers responsible for sending a notice of disconnect to the client and stopping the queue.
     *
     * @param array<string, scalar> $context
     */
    private function installChildSignalHandlers(
        ServerProtocolHandler $protocolHandler,
        array $context,
    ): void {
        foreach ($this->handledSignals as $signal) {
            $context = array_merge(
                $context,
                ['signal' => $signal],
            );
            pcntl_signal(
                $signal,
                function () use ($protocolHandler, $context) {
                    // Ignore it if a signal was already acknowledged...
                    if ($this->isShuttingDown) {
                        return;
                    }
                    $this->isShuttingDown = true;
                    $this->logInfo(
                        'The child process has received a signal to stop.',
                        $context,
                    );
                    try {
                        $protocolHandler->shutdown();
                    } catch (Throwable $e) {
                        $this->logShutdownNotifyError($e, $context);
                    }
                },
            );
        }
        // Children don't reload config; ignore SIGHUP so terminal hangups don't kill them.
        pcntl_signal(
            SIGHUP,
            SIG_IGN,
        );
    }

    private function isOwnerProcess(): bool
    {
        return posix_getpid() === $this->ownerPid;
    }

    private function blockSignals(): void
    {
        pcntl_sigprocmask(
            SIG_BLOCK,
            $this->blockableSignals(),
        );
    }

    private function unblockSignals(): void
    {
        pcntl_sigprocmask(
            SIG_UNBLOCK,
            $this->blockableSignals(),
        );
    }

    /**
     * @return int[]
     */
    private function blockableSignals(): array
    {
        return [
            ...$this->handledSignals,
            SIGHUP,
        ];
    }

    /**
     * Install signal handlers responsible for ending all child processes gracefully, sending a SIG_KILL if necessary.
     */
    private function installServerSignalHandlers(): void
    {
        foreach ($this->handledSignals as $signal) {
            pcntl_signal(
                $signal,
                function () {
                    $this->handleServerShutdown();
                },
            );
        }
        pcntl_signal(
            SIGHUP,
            function () {
                if (!$this->isOwnerProcess()) {
                    return;
                }

                $this->metricsRecorder->serverReloaded(time());
                $this->reloadConfiguration($this->defaultContext);
                $this->publishMetricsSnapshot();
            },
        );
    }

    /**
     * Attempts to shut down the server end all child processes in a graceful way...
     *
     *     1. Set a marker on the class signaling we are shutting down. This will reject incoming clients.
     *     2. First sends a SIG_TERM to all child processes asking them to shut down and send a notice to the client.
     *     3. Waits for child processes to stop / clean them up.
     *     4. Force ends any remaining child process after a max time by sending a SIG_KILL.
     *     5. Cleans up any child socket resources.
     *     6. Stops the main socket server process.
     */
    private function handleServerShutdown(): void
    {
        if (!$this->isOwnerProcess()) {
            return;
        }
        // Want to make sure we are only handling this once...
        if ($this->isShuttingDown) {
            return;
        }
        $this->isShuttingDown = true;
        $this->logShutdownStarted($this->defaultContext);

        // Ask nicely first...
        $this->backgroundTasks->stop();
        $this->endChildProcesses(SIGTERM);

        $waitTime = 0;
        while (!empty($this->childProcesses)) {
            // If we reach the shutdown timeout, attempt to force end them and then stop.
            if ($waitTime >= $this->options->getNetworkConfig()->getShutdownTimeout()) {
                $this->forceEndChildProcesses();

                break;
            }
            $this->cleanUpChildProcesses();

            // We are still waiting for some children to shut down, wait on them.
            if (!empty($this->childProcesses)) {
                sleep(1);
                $waitTime += 1;
            }
        }

        $this->server->close();
        $this->snapshotPublisher?->remove();
        $this->logShutdownCompleted($this->defaultContext);
    }

    /**
     * Iterates through each child process and sends the specified signal.
     */
    private function endChildProcesses(
        int $signal,
        bool $closeSocket = false,
    ): void {
        foreach ($this->childProcesses as $childProcess) {
            $context = array_merge(
                $this->defaultContext,
                ['child_pid' => $childProcess->getPid()],
            );

            $message = ($signal === SIGKILL)
                ? 'Force ending child process.'
                : 'Sending graceful signal to end child process.';
            $this->logInfo(
                $message,
                $context,
            );

            posix_kill(
                $childProcess->getPid(),
                $signal,
            );
            if ($closeSocket) {
                $childProcess->closeSocket();
            }
        }
    }

    /**
     * In the child process we install a different set of signal handlers. Then we run the protocol handler and exit
     * with a zero error code.
     *
     * @throws EncoderException
     */
    private function runChildProcessThenExit(
        Socket $socket,
        int $pid,
        ?ChildChannel $channel,
    ): never {
        // Cleanup the inherited FD copies without disturbing the accept loop or the connections still in flight.
        $this->server->close(shutdown: false);
        $this->closeInheritedConnections();
        $channel?->childKeepWrite();
        if ($channel !== null) {
            $this->operationRollup?->enterChild($channel);
        }

        $context = ['pid' => $pid];
        $this->isMainProcess = false;

        $this->resettable?->reset();

        if (!$this->encryptConnectionIfDeferred($socket, $context)) {
            $socket->close();

            exit(0);
        }

        $serverProtocolHandler = $this->serverProtocolFactory->make(
            $socket,
            new ConnectionContext(pid: $pid),
        );

        $this->installChildSignalHandlers(
            $serverProtocolHandler,
            $context,
        );
        $this->unblockSignals();

        $this->logInfo(
            'Handling LDAP connection in new child process.',
            $context,
        );

        $closeReason = null;
        try {
            $closeReason = $serverProtocolHandler->handle();
        } finally {
            $this->operationRollup?->finish();
        }

        $this->logInfo(
            'The child process is ending.',
            $context,
        );

        // Convey a timeout close to the parent through the exit code.
        exit($this->childExitCodeFor($closeReason));
    }

    /**
     * Prepare a freshly forked background-task child: drop the inherited server socket, connections and signal
     * handlers, then reset inherited per-connection state.
     */
    private function enterChild(): void
    {
        $this->server->close(shutdown: false);
        $this->closeInheritedConnections();
        $this->isMainProcess = false;

        // A sweep child is terminated by SIGTERM; the replica daemon installs its own handlers when it runs.
        foreach ($this->handledSignals as $signal) {
            pcntl_signal(
                $signal,
                SIG_DFL,
            );
        }
        pcntl_signal(
            SIGHUP,
            SIG_IGN,
        );

        $this->resettable?->reset();
    }

    /**
     * Release the channel read ends and client sockets of connections already in flight, so this fork neither leaks
     * them nor ends them when it exits.
     */
    private function closeInheritedConnections(): void
    {
        foreach ($this->childProcesses as $childProcess) {
            $childProcess->getChannel()?->close();
            $childProcess->releaseSocket();
        }

        $this->childProcesses = [];
    }

    /**
     * Negotiate TLS for connections whose handshake the listener left to the handler.
     *
     * @param array<string, mixed> $context
     */
    private function encryptConnectionIfDeferred(
        Socket $socket,
        array $context,
    ): bool {
        if (!$this->socketServerFactory->isTlsHandshakeDeferred()) {
            return true;
        }

        try {
            $socket->encrypt(true);
        } catch (Throwable $e) {
            $this->logTlsHandshakeError($e, $context);

            return false;
        }

        return true;
    }

    private function makeChildChannel(): ?ChildChannel
    {
        if ($this->operationRollup === null) {
            return null;
        }

        try {
            return $this->operationRollup->openChannel();
        } catch (RuntimeException $e) {
            $this->logInfo(
                'Unable to create a child metrics channel; continuing without operation rollup.',
                array_merge(
                    $this->defaultContext,
                    ['error' => $e->getMessage()],
                ),
            );

            return null;
        }
    }

    /**
     * When a new Socket is received, we do the following:
     *
     *     1. Add the ChildProcess to the list of running child processes.
     *     2. Clean-up any currently running child processes.
     */
    private function runAfterChildStarted(
        int $pid,
        Socket $socket,
        ?ChildChannel $channel,
    ): void {
        $channel?->parentKeepRead();
        $this->childProcesses[] = new ChildProcess(
            $pid,
            $socket,
            $channel,
        );
        $this->metricsRecorder->connectionObserved(ConnectionObservation::Opened);
        $this->logClientConnected(
            array_merge(
                ['child_pid' => $pid],
                $this->defaultContext,
            ),
        );
        $this->cleanUpChildProcesses();
    }

    /**
     * After try to stop processes nicely, we instead:
     *
     *      1. Clean up and existing processes.
     *      2. Send a SIG_KILL to each child.
     *      3. Clean up the list of child processes.
     */
    private function forceEndChildProcesses(): void
    {
        // One last check before we force end them all.
        $this->cleanUpChildProcesses();
        if (empty($this->childProcesses)) {
            return;
        }

        $this->endChildProcesses(
            SIGKILL,
            true,
        );
        $this->cleanUpChildProcesses();
    }

    private function getRunnerLogger(): ?LoggerInterface
    {
        return $this->options->getLogger();
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logInfo(
        string $message,
        array $context = [],
    ): void {
        $this->options->getLogger()?->log(
            LogLevel::INFO,
            $message,
            $context,
        );
    }

    /**
     * @param array<string, mixed> $context
     * @throws RuntimeException
     */
    private function logAndThrow(
        string $message,
        array $context = [],
    ): never {
        $this->options->getLogger()?->log(LogLevel::ERROR, $message, $context);

        throw new RuntimeException($message);
    }
}
