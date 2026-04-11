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

use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Bind\AnonymousBind;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchange;
use FreeDSx\Ldap\Protocol\Bind\SaslBind;
use FreeDSx\Ldap\Protocol\Bind\SimpleBind;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Sasl\Sasl;
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

        $backend = $this->handlerFactory->makeBackend();
        $passwordAuthenticator = $this->handlerFactory->makePasswordAuthenticator();

        $authenticators = [
            new SimpleBind(
                queue: $serverQueue,
                authenticator: $passwordAuthenticator,
            ),
            new AnonymousBind($serverQueue),
        ];
        $saslMechanisms = $this->options->getSaslMechanisms();

        if (!empty($saslMechanisms)) {
            $responseFactory = new ResponseFactory();
            $authenticators[] = new SaslBind(
                queue: $serverQueue,
                exchange: new SaslExchange(
                    $serverQueue,
                    $responseFactory,
                    new MechanismOptionsBuilderFactory($passwordAuthenticator),
                ),
                sasl: new Sasl(['supported' => $saslMechanisms]),
                mechanisms: $saslMechanisms,
                responseFactory: $responseFactory,
            );
        }

        return new ServerProtocolHandler(
            queue: $serverQueue,
            protocolHandlerFactory: new ServerProtocolHandlerFactory(
                handlerFactory: $this->handlerFactory,
                options: $this->options,
                requestHistory: new RequestHistory(),
                queue: $serverQueue,
            ),
            authorizer: $this->serverAuthorization,
            authenticator: new Authenticator($authenticators),
            logger: $this->options->getLogger(),
        );
    }
}
