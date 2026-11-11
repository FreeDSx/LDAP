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

namespace Tests\Support\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Socket\SocketServer;
use FreeDSx\Socket\SocketServerOptions;

/**
 * Binds listening servers whose first accepts fail, each server counting its own.
 */
final readonly class FailingAcceptSocketServerFactory extends SocketServerFactory
{
    public function __construct(
        NetworkConfig $network,
        RunnerMode $runner,
        EventLogger $eventLogger,
        bool $reusePort,
        private int $failingAccepts,
    ) {
        parent::__construct(
            $network,
            $runner,
            $eventLogger,
            $reusePort,
        );
    }

    protected function bind(
        string $resource,
        ?int $port,
        SocketServerOptions $options,
    ): SocketServer {
        return (new FailingAcceptSocketServer(
            $options,
            $this->failingAccepts,
        ))->listen(
            $resource,
            $port,
        );
    }
}
