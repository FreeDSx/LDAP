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
                // In parent process, but could not fork....
                throw new RuntimeException('Unable to fork process.');
            } elseif ($pid === 0) {
                // This is the child's thread of execution...
                $this->isServer = false;
                $this->handleSocket($socket);
            } else {
                // We are in the parent; the PID is the child process.
                $this->childProcesses[] = new ChildProcess(
                    $pid,
                    $socket
                );
                $this->cleanUpChildProcesses();
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
        exit;
    }
}
