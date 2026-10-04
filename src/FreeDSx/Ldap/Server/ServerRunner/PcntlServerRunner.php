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
use FreeDSx\Ldap\Server\Backend\NonResettable;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\Process\BackgroundTask\PcntlBackgroundTasks;
use FreeDSx\Ldap\Server\Process\Child\ChildExitCode;
use FreeDSx\Ldap\Server\Process\Child\ChildProcess;
use FreeDSx\Ldap\Server\Process\Child\ChildProcesses;
use FreeDSx\Ldap\Server\Process\Child\ReapedChild;
use FreeDSx\Ldap\Server\ServerRunner\Pcntl\ChildReporter;
use FreeDSx\Ldap\Server\ServerRunner\Pcntl\MetricsRelay;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketServer;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
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

    private SocketServer $server;

    private ChildProcesses $childProcesses;

    private bool $isMainProcess = true;

    /**
     * Used to guard against certain handlers only the owning PID should run.
     */
    private readonly int $ownerPid;

    /**
     * @var int[] These are the POSIX signals we handle for shutdown purposes.
     */
    private array $handledSignals;

    private bool $isShuttingDown = false;

    private readonly BackgroundTasksInterface $backgroundTasks;

    /**
     * @var array<string, mixed>
     */
    private array $defaultContext = [];

    public function __construct(
        private readonly RunnerConfiguration $configuration,
        private readonly SocketServerFactory $socketServerFactory,
        private readonly MetricsRelay $metrics = new MetricsRelay(),
        private readonly ResettableInterface $resettable = new NonResettable(),
        BackgroundTasksInterface $backgroundTasks = new PcntlBackgroundTasks(
            periodicTasks: [],
            longLivedTasks: [],
        ),
    ) {
        $this->childProcesses = new ChildProcesses();

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
        $this->metrics->prepare();
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

    private function isConnectionLimitReached(): bool
    {
        $maxConnections = $this->options()
            ->getNetworkConfig()
            ->getMaxConnections();

        return $maxConnections > 0
            && count($this->childProcesses) >= $maxConnections;
    }

    /**
     * Reaps the children that have ended, so none is left a zombie, and refreshes cn=monitor from the rest.
     */
    private function cleanUpChildProcesses(): void
    {
        $reaped = $this->childProcesses->reapExited();

        foreach ($reaped as $child) {
            $this->releaseReapedChild($child);
        }

        $this->metrics->sweep(
            $reaped,
            $this->childProcesses->all(),
        );
    }

    private function releaseReapedChild(ReapedChild $reaped): void
    {
        $socket = $reaped->process->getSocket();
        $this->server->removeClient($socket);
        $socket->close();

        $this->logInfo(
            'The child process has ended.',
            array_merge(
                $this->defaultContext,
                ['child_pid' => $reaped->process->getPid()],
            ),
        );
    }

    /**
     * Accept clients from the socket server in a loop with a timeout. This lets us to periodically check existing
     * children processes as we listen for new ones.
     */
    private function acceptClients(): void
    {
        $this->installServerSignalHandlers();
        $this->logServerStarted($this->defaultContext);
        $this->metrics->serverStarted();
        $this->options()->getOnServerReady()?->__invoke();
        $this->backgroundTasks->start();

        do {
            $this->backgroundTasks->tick();
            $socket = $this->server->accept($this->options()->getNetworkConfig()->getSocketAcceptTimeout());

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

            if ($this->isConnectionLimitReached()) {
                $this->cleanUpChildProcesses();
            }

            if ($this->isConnectionLimitReached()) {
                $this->logConnectionLimitReached($this->defaultContext);
                $this->metrics->connectionRejected();

                $this->server->removeClient($socket);
                $socket->close();

                continue;
            }

            $reporter = $this->metrics->openChildReporter();

            // A child inherits the parent's handlers. Block them until it has installed its own.
            $this->blockSignals();

            $pid = pcntl_fork();
            if ($pid == -1) {
                // In parent process, but could not fork...
                $this->unblockSignals();
                $reporter?->close();
                $this->logAndThrow(
                    'Unable to fork process.',
                    $this->defaultContext,
                );
            } elseif ($pid === 0) {
                // This is the child's thread of execution...
                $this->runChildProcessThenExit(
                    $socket,
                    posix_getpid(),
                    $reporter,
                );
            } else {
                // We are in the parent; the PID is the child process. It is tracked before signals are unblocked, so
                $this->runAfterChildStarted(
                    $pid,
                    $socket,
                    $reporter,
                );
                $this->unblockSignals();
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
        // Children ignore SIGHUP so terminal hangups don't kill them; the parent asks them to reload with SIGUSR1.
        pcntl_signal(
            SIGHUP,
            SIG_IGN,
        );
        pcntl_signal(
            SIGUSR1,
            fn() => $this->reloadInChild(
                $protocolHandler,
                array_merge(
                    $context,
                    ['signal' => SIGUSR1],
                ),
            ),
        );
    }

    /**
     * The parent already reloaded, so a child that cannot follow ends its session rather than keep the old policy.
     *
     * @param array<string, scalar> $context
     */
    private function reloadInChild(
        ServerProtocolHandler $protocolHandler,
        array $context,
    ): void {
        if ($this->isShuttingDown) {
            return;
        }

        if ($this->configuration->follow($context)) {
            $this->logInfo(
                'The child process applied the reloaded configuration.',
                $context,
            );

            return;
        }

        $this->isShuttingDown = true;
        try {
            $protocolHandler->endAsUnavailable();
        } catch (Throwable $e) {
            $this->logShutdownNotifyError($e, $context);
        }
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
            SIGUSR1,
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

                if (!$this->configuration->reload($this->defaultContext)) {
                    return;
                }

                $this->signalChildProcessesToReload();
                $this->metrics->serverReloaded();
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
        while (!$this->childProcesses->isEmpty()) {
            // If we reach the shutdown timeout, attempt to force end them and then stop.
            if ($waitTime >= $this->options()->getNetworkConfig()->getShutdownTimeout()) {
                $this->forceEndChildProcesses();

                break;
            }
            $this->cleanUpChildProcesses();

            // We are still waiting for some children to shut down, wait on them.
            if (!$this->childProcesses->isEmpty()) {
                sleep(1);
                $waitTime += 1;
            }
        }

        $this->server->close();
        $this->metrics->remove();
        $this->logShutdownCompleted($this->defaultContext);
    }

    private function signalChildProcessesToReload(): void
    {
        foreach ($this->childProcesses->all() as $childProcess) {
            $childProcess->signal(SIGUSR1);
        }
    }

    /**
     * Iterates through each child process and sends the specified signal.
     */
    private function endChildProcesses(
        int $signal,
        bool $closeSocket = false,
    ): void {
        foreach ($this->childProcesses->all() as $childProcess) {
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

            $childProcess->signal($signal);
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
        ?ChildReporter $reporter,
    ): never {
        // Cleanup the inherited FD copies without disturbing the accept loop or the connections still in flight.
        $this->server->close(shutdown: false);
        $this->childProcesses->releaseInherited();
        $reporter?->inChild();

        $context = ['pid' => $pid];
        $this->isMainProcess = false;

        $this->resettable->reset();

        if (!$this->encryptConnectionIfDeferred($socket, $context)) {
            $socket->close();

            exit(0);
        }

        $serverProtocolHandler = $this->configuration->protocolFactory()->make(
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
            $reporter?->finish();
        }

        $this->logInfo(
            'The child process is ending.',
            $context,
        );

        // Convey a timeout close to the parent through the exit code.
        exit(ChildExitCode::forCloseReason($closeReason));
    }

    /**
     * Prepare a freshly forked background-task child: drop the inherited server socket, connections and signal
     * handlers, then reset inherited per-connection state.
     */
    private function enterChild(): void
    {
        $this->server->close(shutdown: false);
        $this->childProcesses->releaseInherited();
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

        $this->resettable->reset();
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

    /**
     * When a new Socket is received, we do the following:
     *
     *     1. Add the ChildProcess to the list of running child processes.
     *     2. Clean-up any currently running child processes.
     */
    private function runAfterChildStarted(
        int $pid,
        Socket $socket,
        ?ChildReporter $reporter,
    ): void {
        $reporter?->inParent();
        $this->childProcesses->add(new ChildProcess(
            $pid,
            $socket,
            $reporter?->channel(),
        ));
        $this->metrics->childStarted();
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
        if ($this->childProcesses->isEmpty()) {
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
        return $this->options()->getLogger();
    }

    private function options(): ServerListenerOptionsInterface
    {
        return $this->configuration->options();
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logInfo(
        string $message,
        array $context = [],
    ): void {
        $this->options()->getLogger()?->log(
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
        $this->options()->getLogger()?->log(LogLevel::ERROR, $message, $context);

        throw new RuntimeException($message);
    }
}
