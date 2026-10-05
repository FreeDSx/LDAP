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

namespace FreeDSx\Ldap\Server\ServerRunner\Swoole;

use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\RunnerConfiguration;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared\ReloadState;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

/**
 * A worker's configuration. Keeps up to date with reloads its pool has applied.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class WorkerConfiguration
{
    public function __construct(
        private RunnerConfiguration $configuration,
        private ReloadState $reloadState,
    ) {}

    public function options(): ServerListenerOptionsInterface
    {
        return $this->configuration->options();
    }

    public function protocolFactory(): ServerProtocolFactoryInterface
    {
        return $this->configuration->protocolFactory();
    }

    public function events(): EventLogger
    {
        return $this->configuration->events();
    }

    /**
     * The startup options are current only until a reload.
     *
     * @param array<string, scalar> $context
     * @return bool whether the worker may serve
     */
    public function adoptOnStart(array $context): bool
    {
        if (!$this->reloadState->hasReloaded() || $this->configuration->reload($context)) {
            return true;
        }

        $this->events()->record(
            ServerEvent::ReloadAdoptFailed,
            $context,
        );

        return false;
    }

    /**
     * A failed reload keeps the current configuration.
     *
     * @param array<string, scalar> $context
     * @return bool whether a new configuration was adopted
     */
    public function reload(array $context): bool
    {
        if (!$this->configuration->reload($context)) {
            return false;
        }
        $this->reloadState->markReloaded();

        return true;
    }
}
