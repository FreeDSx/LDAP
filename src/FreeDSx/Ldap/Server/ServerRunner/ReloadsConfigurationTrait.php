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
 * Holds a runner's live configuration and adopts a reloaded one when the ReloadCoordinator produces it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ReloadsConfigurationTrait
{
    private ServerListenerOptionsInterface $options;

    private ServerProtocolFactoryInterface $serverProtocolFactory;

    /**
     * @var Closure(ServerListenerOptionsInterface): ServerProtocolFactoryInterface
     */
    private Closure $protocolFactoryProvider;

    /**
     * Adopts a reloaded configuration for new connections. In-flight connections keep their current config.
     *
     * @param array<string, mixed> $context
     */
    private function reloadConfiguration(array $context = []): void
    {
        $result = (new ReloadCoordinator())->reload(
            $this->options,
            $this->protocolFactoryProvider,
            $context,
        );

        if ($result === null) {
            return;
        }

        $this->options = $result->options;
        $this->serverProtocolFactory = $result->protocolFactory;
    }
}
