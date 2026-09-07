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

namespace FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\Bind\SimpleBind;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerStartTlsHandler;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Middleware\AuthorizationResolutionMiddleware;
use FreeDSx\Ldap\Server\Middleware\BindMiddleware;
use FreeDSx\Ldap\Server\Middleware\ConfidentialityMiddleware;
use FreeDSx\Ldap\Server\Middleware\CriticalControlValidator;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareChain;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Middleware\RequestValidationMiddleware;
use FreeDSx\Ldap\Server\ServerConnectionScaffoldingTrait;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Socket\Socket;

/**
 * Builds a per-connection protocol handler that forwards operations to an upstream LDAP server.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ProxyProtocolFactory implements ServerProtocolFactoryInterface
{
    use ServerConnectionScaffoldingTrait;

    private readonly ServerListenerOptionsInterface $options;

    public function __construct(
        private readonly ProxyOptions $proxyOptions,
        private readonly SleeperInterface $sleeper = new BlockingSleeper(),
    ) {
        $this->options = $proxyOptions->getServerOptions();
    }

    public function make(
        Socket $socket,
        ConnectionContext $context = new ConnectionContext(),
    ): ServerProtocolHandler {
        $queue = $this->makeServerQueue($socket);
        $eventLogger = $this->makeEventLogger($context);
        $upstream = new LdapClient($this->proxyOptions->getClientOptions());
        $serverAuthorization = new ServerAuthorization($this->options);
        $session = new ProxyUpstreamSession(
            client: $upstream,
            useStartTls: $this->proxyOptions->getUseStartTls(),
            sleeper: $this->sleeper,
        );

        $authenticators = [
            new SimpleBind(
                queue: $queue,
                authenticator: new ProxyAuthenticator($session),
                eventLogger: $eventLogger,
            ),
            $this->makeAnonymousBind(
                $queue,
                $eventLogger,
            ),
        ];

        $pipeline = new MiddlewareChain(
            [
                new RequestValidationMiddleware(),
                // Ahead of the bind, so a credential is refused before it is read rather than after it is compared.
                new ConfidentialityMiddleware(
                    $this->options,
                    $queue,
                ),
                new ProxyBindResetMiddleware(
                    $serverAuthorization,
                    $session,
                ),
                new BindMiddleware(
                    $serverAuthorization,
                    new Authenticator($authenticators, $queue),
                    new CriticalControlValidator(),
                ),
                new AuthorizationResolutionMiddleware(
                    new DispatchAuthorizer($serverAuthorization),
                ),
            ],
            new ProxyRequestPipeline(
                new ServerStartTlsHandler(
                    $this->options,
                    $queue,
                    $eventLogger,
                ),
                new ProxyRequestForwarder(
                    $upstream,
                    $queue,
                    $session,
                ),
                new ResponseWriter($queue),
            ),
        );

        return new ServerProtocolHandler(
            queue: $queue,
            requestPipeline: $pipeline,
            sessionEndPolicy: $this->makeSessionEndPolicy(
                $queue,
                $eventLogger,
            ),
            eventLogger: $eventLogger,
            connectionContext: $context,
        );
    }

    protected function serverOptions(): ServerListenerOptionsInterface
    {
        return $this->options;
    }
}
