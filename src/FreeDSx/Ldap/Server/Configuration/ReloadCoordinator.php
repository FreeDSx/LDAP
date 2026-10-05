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
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Ldap\ServerOptions;
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
            self::events($current)->record(
                ServerEvent::ReloadFailed,
                $context,
                cause: $e,
            );

            return null;
        }

        self::events($current)->record(
            ServerEvent::ReloadApplied,
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
            self::events($current)->record(
                ServerEvent::ReloadIgnored,
                $context + [EventContext::REASON => 'unsupported'],
            );

            return null;
        }

        $reloader = $current->getConfigReloader();

        if ($reloader === null) {
            self::events($current)->record(
                ServerEvent::ReloadIgnored,
                $context + [EventContext::REASON => 'no_reloader'],
            );

            return null;
        }

        try {
            return $reloader->reload($current);
        } catch (Throwable $e) {
            self::events($current)->record(
                ServerEvent::ReloadFailed,
                $context,
                cause: $e,
            );

            return null;
        }
    }

    private static function events(ServerListenerOptionsInterface $current): EventLogger
    {
        return new EventLogger(
            $current->getLogger(),
            $current->getEventLogPolicy(),
        );
    }
}
