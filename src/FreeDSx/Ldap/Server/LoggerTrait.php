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

namespace FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\ServerOptions;
use Psr\Log\LogLevel;

/**
 * Some simple logging methods. Only logs if we have a logger in the options.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait LoggerTrait
{
    private ServerOptions $options;

    /**
     * Logs a message and then throws a runtime exception.
     *
     * @throws RuntimeException
     */
    private function logAndThrow(
        string $message,
        array $context = []
    ): void {
        $this->log(
            level: LogLevel::ERROR,
            message: $message,
            context: $context
        );

        throw new RuntimeException($message);
    }

    /**
     * @param array<string, mixed> $context
     */
    protected function logError(
        string $message,
        array $context = []
    ): void {
        $this->log(
            level: LogLevel::ERROR,
            message: $message,
            context: $context,
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    protected function logInfo(
        string $message,
        array $context = []
    ): void {
        $this->log(
            level: LogLevel::INFO,
            message:$message,
            context: $context,
        );
    }

    /**
     * Log a message with a level and context (if we have a logger).
     *
     * @param array<string, mixed> $context
     */
    private function log(
        string $level,
        string $message,
        array $context = []
    ): void {
        $this->options->getLogger()?->log(
            level: $level,
            message: $message,
            context: $context,
        );
    }
}
