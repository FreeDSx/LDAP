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

use Closure;
use FreeDSx\Ldap\Server\Configuration\ReloadCoordinator;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

/**
 * The configuration a runner process serves under.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class RunnerConfiguration
{
    /**
     * @param Closure(ServerListenerOptionsInterface): ServerProtocolFactoryInterface $protocolFactoryProvider
     * @param Closure(ServerListenerOptionsInterface): void $applyReload Applies what open connections must follow.
     */
    public function __construct(
        private ServerListenerOptionsInterface $options,
        private ServerProtocolFactoryInterface $protocolFactory,
        private readonly Closure $protocolFactoryProvider,
        private readonly Closure $applyReload,
    ) {}

    public function options(): ServerListenerOptionsInterface
    {
        return $this->options;
    }

    public function protocolFactory(): ServerProtocolFactoryInterface
    {
        return $this->protocolFactory;
    }

    /**
     * Replaces what new connections are served under, and applies what open ones must follow; a failure keeps both.
     *
     * @param array<string, mixed> $context
     * @return bool whether a new configuration was adopted
     */
    public function reload(array $context): bool
    {
        $result = (new ReloadCoordinator())->reload(
            $this->options,
            $this->protocolFactoryProvider,
            $context,
        );
        if ($result === null) {
            return false;
        }

        $this->options = $result->options;
        $this->protocolFactory = $result->protocolFactory;
        ($this->applyReload)($this->options);

        return true;
    }

    /**
     * For a process that serves only the connections it already has: runs the reloader and applies what they must follow.
     *
     * @param array<string, mixed> $context
     * @return bool whether the reload was applied
     */
    public function follow(array $context): bool
    {
        $reloaded = (new ReloadCoordinator())->reloadOptions(
            $this->options,
            $context,
        );
        if ($reloaded === null) {
            return false;
        }

        ($this->applyReload)($reloaded);

        return true;
    }
}
