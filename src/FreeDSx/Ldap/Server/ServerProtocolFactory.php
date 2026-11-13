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

namespace FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Socket\Socket;

/**
 * Resolves each accepted connection's protocol handler from its own connection scope.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerProtocolFactory implements ServerProtocolFactoryInterface
{
    public function __construct(
        private Container $container,
    ) {}

    public function make(
        Socket $socket,
        ConnectionContext $context = new ConnectionContext(),
    ): ServerProtocolHandler {
        return $this->container
            ->forConnection(
                $socket,
                $context,
            )
            ->get(ServerProtocolHandler::class);
    }
}
