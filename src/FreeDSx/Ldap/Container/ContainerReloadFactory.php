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

namespace FreeDSx\Ldap\Container;

use Closure;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

/**
 * Rebuilds a container of the same server type from reloaded options, captured at seed time so the shared listener
 * provider never branches on server type.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ContainerReloadFactory
{
    /**
     * @param Closure(ServerListenerOptionsInterface, array<class-string, object>): Container $rebuild
     */
    public function __construct(
        private readonly Closure $rebuild,
    ) {}

    /**
     * @param array<class-string, object> $sharedInstances
     */
    public function rebuild(
        ServerListenerOptionsInterface $options,
        array $sharedInstances,
    ): Container {
        return ($this->rebuild)(
            $options,
            $sharedInstances,
        );
    }
}
