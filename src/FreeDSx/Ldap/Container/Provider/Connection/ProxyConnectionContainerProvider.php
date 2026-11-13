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

namespace FreeDSx\Ldap\Container\Provider\Connection;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Container\Provider\ContainerProviderInterface;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\Bind\AnonymousBind;
use FreeDSx\Ldap\Protocol\Bind\SimpleBind;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\Queue\ReadAheadBuffer;
use FreeDSx\Ldap\Protocol\Queue\RequestArrival;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerStartTlsHandler;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Middleware\AuthorizationResolutionMiddleware;
use FreeDSx\Ldap\Server\Middleware\BindMiddleware;
use FreeDSx\Ldap\Server\Middleware\ConfidentialityMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareChain;
use FreeDSx\Ldap\Server\Middleware\RequestValidationMiddleware;
use FreeDSx\Ldap\Server\Proxy\ProxyAuthenticator;
use FreeDSx\Ldap\Server\Proxy\ProxyBindResetMiddleware;
use FreeDSx\Ldap\Server\Proxy\ProxyRequestForwarder;
use FreeDSx\Ldap\Server\Proxy\ProxyRequestPipeline;
use FreeDSx\Ldap\Server\Proxy\ProxyUpstreamSession;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Socket\Socket;

/**
 * Registers the connection-scoped services that compose a proxy server's protocol handler.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ProxyConnectionContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            ServerQueue::class => $this->makeServerQueue(...),
            LdapClient::class => static fn(Container $container): LdapClient => new LdapClient(
                $container->get(ProxyOptions::class)->getClientOptions(),
            ),
            ProxyUpstreamSession::class => $this->makeUpstreamSession(...),
            SimpleBind::class => $this->makeSimpleBind(...),
            Authenticator::class => $this->makeAuthenticator(...),
            DispatchAuthorizer::class => static fn(Container $container): DispatchAuthorizer => new DispatchAuthorizer(
                $container->get(ServerAuthorization::class),
            ),
            ProxyBindResetMiddleware::class => $this->makeBindResetMiddleware(...),
            AuthorizationResolutionMiddleware::class => static fn(Container $container): AuthorizationResolutionMiddleware => new AuthorizationResolutionMiddleware(
                $container->get(DispatchAuthorizer::class),
            ),
            ProxyRequestPipeline::class => $this->makeRequestPipeline(...),
            MiddlewareChain::class => $this->makeMiddlewareChain(...),
        ];
    }

    private function makeServerQueue(Container $container): ServerQueue
    {
        return new ServerQueue(
            socket: $container->get(Socket::class),
            messageDecoder: $container->get(RequestMessageDecoder::class),
            arrival: $container->get(RequestArrival::class),
            readAhead: new ReadAheadBuffer(),
        );
    }

    private function makeUpstreamSession(Container $container): ProxyUpstreamSession
    {
        return new ProxyUpstreamSession(
            client: $container->get(LdapClient::class),
            useStartTls: $container->get(ProxyOptions::class)->getUseStartTls(),
        );
    }

    private function makeSimpleBind(Container $container): SimpleBind
    {
        return new SimpleBind(
            queue: $container->get(ServerQueue::class),
            authenticator: new ProxyAuthenticator($container->get(ProxyUpstreamSession::class)),
            eventLogger: $container->get(EventLogger::class),
        );
    }

    private function makeAuthenticator(Container $container): Authenticator
    {
        return new Authenticator(
            [
                $container->get(SimpleBind::class),
                $container->get(AnonymousBind::class),
            ],
            $container->get(ServerQueue::class),
        );
    }

    private function makeBindResetMiddleware(Container $container): ProxyBindResetMiddleware
    {
        return new ProxyBindResetMiddleware(
            $container->get(ServerAuthorization::class),
            $container->get(ProxyUpstreamSession::class),
        );
    }

    private function makeRequestPipeline(Container $container): ProxyRequestPipeline
    {
        $queue = $container->get(ServerQueue::class);

        return new ProxyRequestPipeline(
            new ServerStartTlsHandler(
                $container->get(ServerListenerOptionsInterface::class),
                $queue,
                $container->get(EventLogger::class),
            ),
            new ProxyRequestForwarder(
                $container->get(LdapClient::class),
                $queue,
                $container->get(ProxyUpstreamSession::class),
            ),
            $container->get(ResponseWriter::class),
        );
    }

    private function makeMiddlewareChain(Container $container): MiddlewareChain
    {
        return new MiddlewareChain(
            [
                $container->get(RequestValidationMiddleware::class),
                // Refuses a credential sent without confidentiality before the bind reads it.
                $container->get(ConfidentialityMiddleware::class),
                $container->get(ProxyBindResetMiddleware::class),
                $container->get(BindMiddleware::class),
                $container->get(AuthorizationResolutionMiddleware::class),
            ],
            $container->get(ProxyRequestPipeline::class),
        );
    }
}
