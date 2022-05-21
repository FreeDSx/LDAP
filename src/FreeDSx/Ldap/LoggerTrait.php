<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Exception\RuntimeException;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * Some simple logging methods. Only logs if we have a logger in the options.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait LoggerTrait
{
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
            LogLevel::ERROR,
            $message,
            $context
        );

        throw new RuntimeException($message);
    }

    protected function logError(
        string $message,
        array $context = []
    ): void {
        $this->log(
            LogLevel::ERROR,
            $message,
            $context
        );
    }

    protected function logInfo(
        string $message,
        array $context = []
    ): void {
        $this->log(
            LogLevel::INFO,
            $message,
            $context
        );
    }

    /**
     * Log a message with a level and context (if we have a logger).
     *
     * @param string $level
     * @param string $message
     * @param array $context
     */
    private function log(
        string $level,
        string $message,
        array $context = []
    ): void {
        if (isset($this->options['logger']) && $this->options['logger'] instanceof LoggerInterface) {
            $this->options['logger']->log(
                $level,
                $message,
                $context
            );
        }
    }
}
