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

use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Socket\Socket;
use Psr\Log\LoggerInterface;

class ServerProtocolFactory
{
    public function __construct(
        private readonly HandlerFactoryInterface $handlerFactory,
        private readonly ?LoggerInterface $logger,
        private readonly ServerProtocolHandlerFactory $serverProtocolHandlerFactory,
        private readonly ServerAuthorization $serverAuthorization,
    ) {
    }

    public function make(Socket $socket): ServerProtocolHandler
    {
        return new ServerProtocolHandler(
            queue: new ServerQueue($socket),
            handlerFactory: $this->handlerFactory,
            logger: $this->logger,
            protocolHandlerFactory:$this->serverProtocolHandlerFactory,
            authorizer: $this->serverAuthorization,
        );
    }
}
