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

namespace FreeDSx\Ldap\Server\ServerRunner\Pcntl;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Process\Child\ChildExitCode;
use FreeDSx\Ldap\Server\ServerRunner\RunnerConfiguration;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerLoggerTrait;
use FreeDSx\Socket\Socket;
use Psr\Log\LoggerInterface;
use Throwable;

use function array_merge;
use function pcntl_signal;
use function pcntl_sigprocmask;
use function posix_getpid;

/**
 * Serves one connection in the child the forking runner started for it, then exits with how it closed.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ConnectionChild
{
    use ServerRunnerLoggerTrait;

    private bool $isShuttingDown = false;

    /**
     * @param list<int> $shutdownSignals Each ends the session with a notice of disconnection.
     * @param list<int> $blockedSignals What the parent blocked around the fork, unblocked once the handlers are in place.
     */
    public function __construct(
        private readonly RunnerConfiguration $configuration,
        private readonly ResettableInterface $resettable,
        private readonly bool $isTlsHandshakeDeferred,
        private readonly array $shutdownSignals,
        private readonly array $blockedSignals,
    ) {}

    /**
     * @throws EncoderException
     */
    public function run(
        Socket $socket,
        ?ChildReporter $reporter,
    ): never {
        $reporter?->inChild();
        $pid = posix_getpid();
        $context = ['pid' => $pid];

        $this->resettable->reset();

        if (!$this->encryptConnectionIfDeferred($socket, $context)) {
            $socket->close();

            exit(0);
        }

        $protocolHandler = $this->configuration->protocolFactory()->make(
            $socket,
            new ConnectionContext(pid: $pid),
        );
        $this->installSignalHandlers(
            $protocolHandler,
            $context,
        );
        pcntl_sigprocmask(
            SIG_UNBLOCK,
            $this->blockedSignals,
        );
        $this->getRunnerLogger()?->info(
            'Handling LDAP connection in new child process.',
            $context,
        );

        $closeReason = null;
        try {
            $closeReason = $protocolHandler->handle();
        } finally {
            $reporter?->finish();
        }

        $this->getRunnerLogger()?->info(
            'The child process is ending.',
            $context,
        );

        // Convey a timeout close to the parent through the exit code.
        exit(ChildExitCode::forCloseReason($closeReason));
    }

    private function getRunnerLogger(): ?LoggerInterface
    {
        return $this->configuration->options()->getLogger();
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
        if (!$this->isTlsHandshakeDeferred) {
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
     * @param array<string, scalar> $context
     */
    private function installSignalHandlers(
        ServerProtocolHandler $protocolHandler,
        array $context,
    ): void {
        foreach ($this->shutdownSignals as $signal) {
            pcntl_signal(
                $signal,
                fn() => $this->shutDown(
                    $protocolHandler,
                    array_merge(
                        $context,
                        ['signal' => $signal],
                    ),
                ),
            );
        }
        // Children ignore SIGHUP so terminal hangups don't kill them; the parent asks them to reload with SIGUSR1.
        pcntl_signal(
            SIGHUP,
            SIG_IGN,
        );
        pcntl_signal(
            SIGUSR1,
            fn() => $this->followReload(
                $protocolHandler,
                array_merge(
                    $context,
                    ['signal' => SIGUSR1],
                ),
            ),
        );
    }

    /**
     * @param array<string, scalar> $context
     */
    private function shutDown(
        ServerProtocolHandler $protocolHandler,
        array $context,
    ): void {
        if ($this->isShuttingDown) {
            return;
        }

        $this->isShuttingDown = true;
        $this->getRunnerLogger()?->info(
            'The child process has received a signal to stop.',
            $context,
        );
        try {
            $protocolHandler->shutdown();
        } catch (Throwable $e) {
            $this->logShutdownNotifyError($e, $context);
        }
    }

    /**
     * The parent already reloaded, so a child that cannot follow ends its session.
     *
     * @param array<string, scalar> $context
     */
    private function followReload(
        ServerProtocolHandler $protocolHandler,
        array $context,
    ): void {
        if ($this->isShuttingDown) {
            return;
        }

        if ($this->configuration->follow($context)) {
            $this->getRunnerLogger()?->info(
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
}
