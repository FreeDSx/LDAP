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

namespace FreeDSx\Ldap\Server\Configuration;

use Closure;
use FreeDSx\Ldap\Server\Logging\ExceptionLogging;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Ldap\ServerOptions;
use Psr\Log\LogLevel;
use Throwable;

/**
 * Drives the config reload process.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ReloadCoordinator
{
    /**
     * Returns the options and factory to adopt for new connections, or null on a no-op (no reloader) or failure.
     *
     * @param Closure(ServerListenerOptionsInterface): ServerProtocolFactoryInterface $protocolFactoryProvider
     * @param array<string, mixed> $context
     */
    public function reload(
        ServerListenerOptionsInterface $current,
        Closure $protocolFactoryProvider,
        array $context = [],
    ): ?ReloadResult {
        $newOptions = $this->reloadOptions(
            $current,
            $context,
        );

        if ($newOptions === null) {
            return null;
        }

        try {
            $protocolFactory = $protocolFactoryProvider($newOptions);
        } catch (Throwable $e) {
            $this->logFailure(
                $current,
                $e,
                $context,
            );

            return null;
        }

        $current->getLogger()?->log(
            LogLevel::INFO,
            'Server configuration reloaded. New connections will use the updated configuration.',
            $context,
        );

        return new ReloadResult(
            $newOptions,
            $protocolFactory,
        );
    }

    /**
     * Runs only the configured reloader, for a process that applies a reload without serving new connections.
     *
     * @param array<string, mixed> $context
     */
    public function reloadOptions(
        ServerListenerOptionsInterface $current,
        array $context = [],
    ): ?ServerOptions {
        if (!$current instanceof ServerOptions) {
            $current->getLogger()?->log(
                LogLevel::INFO,
                'Received a reload signal, but the current server type does not support reloading. Ignoring.',
                $context,
            );

            return null;
        }

        $reloader = $current->getConfigReloader();

        if ($reloader === null) {
            $current->getLogger()?->log(
                LogLevel::INFO,
                'Received a reload signal, but no configuration reloader is configured. Ignoring.',
                $context,
            );

            return null;
        }

        try {
            return $reloader->reload($current);
        } catch (Throwable $e) {
            $this->logFailure(
                $current,
                $e,
                $context,
            );

            return null;
        }
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logFailure(
        ServerListenerOptionsInterface $current,
        Throwable $exception,
        array $context,
    ): void {
        $current->getLogger()?->log(
            LogLevel::ERROR,
            'Configuration reload failed. Keeping the current configuration.',
            $context + ExceptionLogging::makeLogContext($exception),
        );
    }
}
