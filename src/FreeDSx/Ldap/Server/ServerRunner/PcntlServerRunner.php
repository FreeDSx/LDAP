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
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\ChildProcess;
use FreeDSx\Ldap\Server\RequestHandler\HandlerFactory;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketServer;

/**
 * Uses PNCTL to fork incoming requests and send them to the server protocol handler.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PcntlServerRunner implements ServerRunnerInterface
{
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
    protected $isServer = true;

    /**
     * @var null|ChildProcess
     */
    protected $childProcess = null;

    /**
     * @var int[] These are the POSIX signals we handle for shutdown purposes.
     */
    protected $handledSignals = [];

    /**
     * @var bool
     */
    protected $isPosixExtLoaded;

    /**
     * @var bool
     */
    protected $isServerSignalsInstalled = false;

    /**
     * @param array $options
     * @psalm-param array{request_handler?: class-string<RequestHandlerInterface>} $options
     * @throws RuntimeException
     */
    public function __construct(array $options = [])
    {
        if (!extension_loaded('pcntl')) {
            throw new RuntimeException('The PCNTL extension is needed to fork incoming requests, which is only available on Linux.');
        }
        $this->options = $options;

        // posix_kill needs this...we cannot clean up child processes without it on shutdown...
        $this->isPosixExtLoaded = extension_loaded('posix');
        // We need to be able to handle signals as they come in, regardless of what is going on...
        pcntl_async_signals(true);

        $this->handledSignals = [
            SIGHUP,
            SIGINT,
            SIGTERM,
            SIGQUIT,
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
        } finally {
            $this->cleanUpChildProcesses();
        }
    }

    /**
     * Check each child process we have and see if it is stopped. This will clean up zombie processes.
     */
    private function cleanUpChildProcesses(): void
    {
        if (!$this->isServer) {
            return;
        }

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
                $this->server->removeClient($childProcess->getSocket());
            }
        }
    }

    private function acceptClients(): void
    {
        do {
            $socket = $this->server->accept(self::SOCKET_ACCEPT_TIMEOUT);
            $this->cleanUpChildProcesses();

            if ($socket === null) {
                continue;
            }

            $pid = pcntl_fork();
            if ($pid == -1) {
                // In parent process, but could not fork...
                throw new RuntimeException('Unable to fork process.');
            } elseif ($pid === 0) {
                // This is the child's thread of execution...
                $this->startChildProcessAndWait(
                    $pid,
                    $socket
                );

                exit(0);
            } else {
                // We are in the parent; the PID is the child process.
                $this->runAfterChildStarted(
                    $pid,
                    $socket
                );
            }
        } while ($this->server->isConnected());
    }

    /**
     * @param Socket $socket
     * @throws EncoderException
     */
    private function handleSocket(Socket $socket): void
    {
        $serverProtocolHandler = new ServerProtocolHandler(
            new ServerQueue($socket),
            new HandlerFactory($this->options),
            $this->options
        );
        $serverProtocolHandler->handle();
    }

    private function installChildSignalHandlers(): void
    {
        foreach ($this->handledSignals as $signal) {
            pcntl_signal(
                $signal,
                function () {
                    if ($this->childProcess) {
                        $this->childProcess->closeSocket();
                    }
                }
            );
        }
    }

    private function installServerSignalHandlers(): void
    {
        foreach ($this->handledSignals as $signal) {
            $this->isServerSignalsInstalled = pcntl_signal(
                $signal,
                function () {
                    $this->handleServerShutdown();
                }
            );
        }
    }

    private function handleServerShutdown(): void
    {
        // We can't do anything else without the posix ext ... :(
        if (!$this->isPosixExtLoaded) {
            $this->cleanUpChildProcesses();

            return;
        }
        // Ask nicely first...
        $this->endChildProcesses(SIGTERM);

        $waitTime = 0;
        while (!empty($this->childProcess)) {
            $this->cleanUpChildProcesses();

            // We are still waiting for some children to shut down, wait on them.
            if (!empty($this->childProcess)) {
                sleep(5);
                $waitTime += 5;
            }

            // If we reach max wait time, attempt to force end them and then stop.
            if ($waitTime >= self::MAX_SHUTDOWN_WAIT_TIME) {
                $this->forceEndChildProcesses();

                break;
            }
        }

        $this->server->close();
    }

    private function endChildProcesses(int $signal): void
    {
        foreach ($this->childProcesses as $childProcess) {
            posix_kill(
                $childProcess->getPid(),
                $signal
            );
            $childProcess->closeSocket();
        }
    }

    /**
     * @throws EncoderException
     */
    private function startChildProcessAndWait(
        int $pid,
        Socket $socket
    ): void {
        $this->isServer = false;
        $this->childProcess = new ChildProcess(
            $pid,
            $socket
        );
        $this->installChildSignalHandlers();
        $this->handleSocket($socket);
    }

    private function runAfterChildStarted(
        int $pid,
        Socket $socket
    ): void {
        if (!$this->isServerSignalsInstalled) {
            $this->installServerSignalHandlers();
        }
        $this->childProcesses[] = new ChildProcess(
            $pid,
            $socket
        );
        $this->cleanUpChildProcesses();
    }

    private function forceEndChildProcesses(): void
    {
        // One last check before we force end them all.
        $this->cleanUpChildProcesses();
        if (empty($this->childProcesses)) {
            return;
        }

        $this->endChildProcesses(SIGKILL);
        $this->cleanUpChildProcesses();
    }
}
