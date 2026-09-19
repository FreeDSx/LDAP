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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection;

use Closure;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriteScope;
use PDO;

/**
 * Hands the serialized writer its own connection and every other caller the reads connection.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class RoutingPdoConnectionProvider implements PdoConnectionProviderInterface
{
    public function __construct(
        private readonly PdoConnectionProviderInterface $reads,
        private readonly PdoConnectionProviderInterface $writes,
        private readonly WriteScope $scope,
    ) {}

    public function get(): PDO
    {
        return $this->route()->get();
    }

    public function txState(): PdoTxState
    {
        return $this->route()->txState();
    }

    public function onConnectionReleased(Closure $listener): void
    {
        $this->reads->onConnectionReleased($listener);
        $this->writes->onConnectionReleased($listener);
    }

    public function reset(): void
    {
        $this->reads->reset();
        $this->writes->reset();
    }

    /**
     * The writer's connection holds its open transaction, which a reads connection cannot see.
     */
    private function route(): PdoConnectionProviderInterface
    {
        return $this->scope->isActive()
            ? $this->writes
            : $this->reads;
    }
}
