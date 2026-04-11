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

use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Throwable;

/**
 * Shared lifecycle log messages for server runners.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ServerRunnerLoggerTrait
{
    abstract private function getRunnerLogger(): ?LoggerInterface;

    /**
     * @param array<string, mixed> $context
     */
    private function logServerStarted(array $context = []): void
    {
        $this->getRunnerLogger()?->log(
            LogLevel::INFO,
            'The server process has started and is now accepting clients.',
            $context,
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logClientConnected(array $context = []): void
    {
        $this->getRunnerLogger()?->log(
            LogLevel::INFO,
            'A new client has connected.',
            $context,
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logClientClosed(array $context = []): void
    {
        $this->getRunnerLogger()?->log(
            LogLevel::INFO,
            'The client connection has closed.',
            $context,
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logClientRejectedDuringShutdown(array $context = []): void
    {
        $this->getRunnerLogger()?->log(
            LogLevel::INFO,
            'A client was accepted, but the server is shutting down. Closing connection.',
            $context,
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logClientError(
        Throwable $e,
        array $context = [],
    ): void {
        $this->getRunnerLogger()?->log(
            LogLevel::ERROR,
            'Unhandled error while handling client connection.',
            array_merge($context, self::exceptionContext($e)),
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logConnectionLimitReached(array $context = []): void
    {
        $this->getRunnerLogger()?->log(
            LogLevel::WARNING,
            'Connection limit reached, dropping new connection.',
            $context,
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logAcceptError(
        Throwable $e,
        array $context = [],
    ): void {
        $this->getRunnerLogger()?->log(
            LogLevel::ERROR,
            'Failed to accept incoming connection.',
            array_merge($context, self::exceptionContext($e)),
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logShutdownStarted(array $context = []): void
    {
        $this->getRunnerLogger()?->log(
            LogLevel::INFO,
            'The server shutdown process has started.',
            $context,
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logShutdownCompleted(array $context = []): void
    {
        $this->getRunnerLogger()?->log(
            LogLevel::INFO,
            'The server shutdown process has completed.',
            $context,
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logShutdownForceClose(
        int $activeConnections,
        array $context = [],
    ): void {
        $this->getRunnerLogger()?->log(
            LogLevel::WARNING,
            'Shutdown timeout exceeded, forcing close of active connections.',
            array_merge($context, ['active_connections' => $activeConnections]),
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logShutdownNotifyError(
        Throwable $e,
        array $context = [],
    ): void {
        $this->getRunnerLogger()?->log(
            LogLevel::WARNING,
            'Unexpected error while notifying client of shutdown.',
            array_merge($context, self::exceptionContext($e)),
        );
    }

    /**
     * @return array{exception_message: string, exception_class: string, exception_stacktrace: string}
     */
    private static function exceptionContext(Throwable $e): array
    {
        return [
            'exception_message' => $e->getMessage(),
            'exception_class' => $e::class,
            'exception_stacktrace' => $e->getTraceAsString(),
        ];
    }
}
