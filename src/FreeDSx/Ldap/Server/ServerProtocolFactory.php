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

use FreeDSx\Ldap\Protocol\Factory\ServerBindHandlerFactory;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;

class ServerProtocolFactory
{
    public function __construct(
        private readonly HandlerFactoryInterface $handlerFactory,
        private readonly ServerOptions $options,
        private readonly ServerAuthorization $serverAuthorization,
    ) {
    }

    public function make(Socket $socket): ServerProtocolHandler
    {
        $serverQueue = new ServerQueue($socket);

        return new ServerProtocolHandler(
            queue: $serverQueue,
            handlerFactory: $this->handlerFactory,
            logger: $this->options->getLogger(),
            protocolHandlerFactory: new ServerProtocolHandlerFactory(
                handlerFactory: $this->handlerFactory,
                options: $this->options,
                requestHistory: new RequestHistory(),
                queue: $serverQueue,
            ),
            authorizer: $this->serverAuthorization,
            bindHandlerFactory: new ServerBindHandlerFactory($serverQueue),
        );
    }
}
