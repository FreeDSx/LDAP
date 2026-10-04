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

use Closure;
use FreeDSx\Ldap\Server\Configuration\ReloadCoordinator;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared\ReloadState;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

/**
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class WorkerConfiguration
{
    /**
     * @param Closure(ServerListenerOptionsInterface): ServerProtocolFactoryInterface $protocolFactoryProvider
     */
    public function __construct(
        private ServerListenerOptionsInterface $options,
        private ServerProtocolFactoryInterface $protocolFactory,
        private readonly Closure $protocolFactoryProvider,
        private readonly ReloadState $reloadState,
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
     * The startup options are current only until a reload.
     *
     * @param array<string, scalar> $context
     * @return bool whether the worker may serve
     */
    public function adoptOnStart(array $context): bool
    {
        if (!$this->reloadState->hasReloaded() || $this->replace($context)) {
            return true;
        }

        $this->options->getLogger()?->error(
            'The reloaded configuration could not be adopted on start; accepting no connections until a reload succeeds.',
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
        if (!$this->replace($context)) {
            return false;
        }
        $this->reloadState->markReloaded();

        return true;
    }

    /**
     * @param array<string, scalar> $context
     */
    private function replace(array $context): bool
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

        return true;
    }
}
