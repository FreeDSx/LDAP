<?php

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
use FreeDSx\Ldap\LoggerTrait;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\ChildProcess;
use FreeDSx\Ldap\Server\RequestHandler\HandlerFactory;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketServer;
use Throwable;

/**
 * Uses PNCTL to fork incoming requests and send them to the server protocol handler.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PcntlServerRunner implements ServerRunnerInterface
{
    use LoggerTrait;

    /**
     * The time to wait, in seconds, before we run some clean-up tasks to then wait again.
     */
    private const SOCKET_ACCEPT_TIMEOUT = 5;

    /**
     * The max time to wait (in seconds) for any child processes before we force kill them.
     */
    private const MAX_SHUTDOWN_WAIT_TIME = 15;

    /**
     * @var SocketServer
     */
    protected $server;

    /**
     * @var array
     */
    protected $options;

    /**
     * @var ChildProcess[]
     */
    protected $childProcesses = [];

    /**
     * @var bool
     */
    protected $isMainProcess = true;

    /**
     * @var int[] These are the POSIX signals we handle for shutdown purposes.
     */
    protected $handledSignals = [];

    /**
     * @var bool
     */
    protected $isShuttingDown = false;

    /**
     * @var array<string, mixed>
     */
    protected $defaultContext = [];

    /**
     * @param array $options
     * @psalm-param array{request_handler?: class-string<RequestHandlerInterface>} $options
     * @throws RuntimeException
     */
    public function __construct(array $options = [])
    {
        if (!extension_loaded('pcntl') || !extension_loaded('posix')) {
            throw new RuntimeException(
                'The PCNTL and POSIX extensions are needed to fork and manage child processes, which is only available on Linux.'
            );
        }
        $this->options = $options;

        // We need to be able to handle signals as they come in, regardless of what is going on...
        pcntl_async_signals(true);

        $this->handledSignals = [
            SIGHUP,
            SIGINT,
            SIGTERM,
            SIGQUIT,
        ];
        $this->defaultContext = [
            'pid' => posix_getpid(),
        ];
    }

    /**
     * @throws EncoderException
     */
    public function run(SocketServer $server): void
    {
        $this->server = $server;

        try {
            $this->acceptClients();
        } catch (Throwable $e) {
            $this->logError(
                'The server stopped accepting clients due to an error.',
                array_merge(
                    $this->defaultContext,
                    [
                        'error' => $e->getMessage(),
                        'error_class' => get_class($e),
                    ]
                )
            );

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
            // No use for this at the moment, but define it anyway.
            $status = null;

            $result = pcntl_waitpid(
                $childProcess->getPid(),
                $status,
                WNOHANG
            );

            if ($result === -1 || $result > 0) {
                unset($this->childProcesses[$index]);
                $socket = $childProcess->getSocket();
                $this->server->removeClient($socket);
                $socket->close();
                $this->logInfo(
                    'The child process has ended.',
                    array_merge(
                        $this->defaultContext,
                        ['child_pid' => $childProcess->getPid()]
                    )
                );
            }
        }
    }

    /**
     * Accept clients from the socket server in a loop with a timeout. This lets us to periodically check existing
     * children processes as we listen for new ones.
     */
    private function acceptClients(): void
    {
        $this->installServerSignalHandlers();
        $this->logInfo(
            'The server process has started and is now accepting clients.',
            $this->defaultContext
        );

        do {
            $socket = $this->server->accept(self::SOCKET_ACCEPT_TIMEOUT);

            if ($this->isShuttingDown) {
                if ($socket) {
                    $this->logInfo(
                        'A client was accepted, but the server is shutting down. Closing connection.',
                        $this->defaultContext
                    );
                    $socket->close();
                }

                break;
            }

            // If there was no client received, we still want to clean up any children that have stopped.
            if ($socket === null) {
                $this->cleanUpChildProcesses();

                continue;
            }

            if ($this->isClientLimitReached()) {
                $this->cleanUpChildProcesses();
            }
            if ($this->isClientLimitReached()) {
                $this->rejectClient($socket);

                continue;
            }

            $pid = pcntl_fork();
            if ($pid == -1) {
                // In parent process, but could not fork...
                $this->logAndThrow(
                    'Unable to fork process.',
                    $this->defaultContext
                );
            } elseif ($pid === 0) {
                // This is the child's thread of execution...
                $this->runChildProcessThenExit(
                    $socket,
                    posix_getpid()
                );
            } else {
                // We are in the parent; the PID is the child process.
                $this->runAfterChildStarted(
                    $pid,
                    $socket
                );
            }
        } while (!$this->isShuttingDown);
    }

    private function releaseInheritedConnections(Socket $keep): void
    {
        // Dropping the reference to free the descriptors
        foreach ($this->server->getClients() as $client) {
            if ($client !== $keep) {
                $this->server->removeClient($client);
            }
        }
        $this->childProcesses = [];
    }

    private function isClientLimitReached(): bool
    {
        $maxClients = isset($this->options['max_clients'])
            ? (int) $this->options['max_clients']
            : 0;

        return $maxClients > 0 && count($this->childProcesses) >= $maxClients;
    }

    private function rejectClient(Socket $socket): void
    {
        $this->logInfo(
            'The maximum number of clients has been reached. Closing the connection.',
            array_merge(
                $this->defaultContext,
                ['max_clients' => (int) $this->options['max_clients']]
            )
        );
        $this->server->removeClient($socket);
        $socket->close();
    }

    /**
     * Install signal handlers responsible for sending a notice of disconnect to the client and stopping the queue.
     */
    private function installChildSignalHandlers(
        ServerProtocolHandler $protocolHandler,
        array $context
    ): void {
        foreach ($this->handledSignals as $signal) {
            $context = array_merge(
                $context,
                ['signal' => $signal]
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
                        $context
                    );
                    try {
                        $protocolHandler->shutdown($context);
                    } catch (Throwable $e) {
                        $this->logError(
                            'Unable to notify the client of the shutdown.',
                            array_merge(
                                $context,
                                [
                                    'error' => $e->getMessage(),
                                    'error_class' => get_class($e),
                                ]
                            )
                        );
                    }
                }
            );
        }
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
                }
            );
        }
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
        // Want to make sure we are only handling this once...
        if ($this->isShuttingDown) {
            return;
        }
        $this->isShuttingDown = true;
        $this->logInfo(
            'The server shutdown process has started.',
            $this->defaultContext
        );

        // Ask nicely first...
        $this->endChildProcesses(SIGTERM);

        $waitTime = 0;
        while (!empty($this->childProcesses)) {
            // If we reach max wait time, attempt to force end them and then stop.
            if ($waitTime >= self::MAX_SHUTDOWN_WAIT_TIME) {
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
        $this->logInfo(
            'The server shutdown process has completed.',
            $this->defaultContext
        );
    }

    /**
     * Iterates through each child process and sends the specified signal.
     */
    private function endChildProcesses(
        int $signal,
        bool $closeSocket = false
    ): void {
        foreach ($this->childProcesses as $childProcess) {
            $context = array_merge(
                $this->defaultContext,
                ['child_pid' => $childProcess->getPid()]
            );

            $message = ($signal === SIGKILL)
                ? 'Force ending child process.'
                : 'Sending graceful signal to end child process.';
            $this->logInfo(
                $message,
                $context
            );

            posix_kill(
                $childProcess->getPid(),
                $signal
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
        int $pid
    ): void {
        $context = ['pid' => $pid];
        $this->isMainProcess = false;
        $this->releaseInheritedConnections($socket);
        $serverProtocolHandler = new ServerProtocolHandler(
            new ServerQueue($socket),
            new HandlerFactory($this->options),
            $this->options
        );

        $this->installChildSignalHandlers(
            $serverProtocolHandler,
            $context
        );

        $this->logInfo(
            'Handling LDAP connection in new child process.',
            $context
        );
        $serverProtocolHandler->handle();
        $this->logInfo(
            'The child process is ending.',
            $context
        );

        exit(0);
    }

    /**
     * When a new Socket is received, we do the following:
     *
     *     1. Add the ChildProcess to the list of running child processes.
     *     2. Clean-up any currently running child processes.
     */
    private function runAfterChildStarted(
        int $pid,
        Socket $socket
    ): void {
        $this->childProcesses[] = new ChildProcess(
            $pid,
            $socket
        );
        $this->logInfo(
            'A new client has connected.',
            array_merge(
                ['child_pid' => $pid],
                $this->defaultContext
            )
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
            true
        );
        $this->cleanUpChildProcesses();
    }
}
