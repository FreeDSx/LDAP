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
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Bind\AnonymousBind;
use FreeDSx\Ldap\Protocol\DecodeFailureResponder;
use FreeDSx\Ldap\Protocol\DisconnectSender;
use FreeDSx\Ldap\Protocol\Queue\Budget\HeldRequests;
use FreeDSx\Ldap\Protocol\Queue\Budget\RequestBudget;
use FreeDSx\Ldap\Protocol\Queue\RequestArrival;
use FreeDSx\Ldap\Protocol\Queue\RequestLimits;
use FreeDSx\Ldap\Protocol\Queue\Response\OutOfSequenceResponder;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Protocol\SessionEndPolicy;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Middleware\BindMiddleware;
use FreeDSx\Ldap\Server\Middleware\ConfidentialityMiddleware;
use FreeDSx\Ldap\Server\Middleware\CriticalControlValidator;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareChain;
use FreeDSx\Ldap\Server\Middleware\RequestValidationMiddleware;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

/**
 * Registers the connection services shared by both servers, except each one's queue, authenticator and pipeline.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ConnectionScaffoldingContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            ServerAuthorization::class => $this->makeServerAuthorization(...),
            RequestLimits::class => $this->makeRequestLimits(...),
            RequestArrival::class => $this->makeRequestArrival(...),
            EventLogger::class => $this->makeEventLogger(...),
            DecodeFailureResponder::class => $this->makeDecodeFailureResponder(...),
            SessionEndPolicy::class => $this->makeSessionEndPolicy(...),
            AnonymousBind::class => $this->makeAnonymousBind(...),
            ResponseWriter::class => $this->makeResponseWriter(...),
            RequestValidationMiddleware::class => static fn(): RequestValidationMiddleware => new RequestValidationMiddleware(),
            ConfidentialityMiddleware::class => $this->makeConfidentialityMiddleware(...),
            BindMiddleware::class => $this->makeBindMiddleware(...),
            ServerProtocolHandler::class => $this->makeServerProtocolHandler(...),
        ];
    }

    private function makeServerAuthorization(Container $container): ServerAuthorization
    {
        return new ServerAuthorization($container->get(ServerListenerOptionsInterface::class));
    }

    private function makeRequestLimits(Container $container): RequestLimits
    {
        $networkConfig = $container->get(ServerListenerOptionsInterface::class)->getNetworkConfig();

        return new RequestLimits(
            authorization: $container->get(ServerAuthorization::class),
            maxSize: $networkConfig->getMaxRequestSize(),
            maxAnonymousSize: $networkConfig->getMaxAnonymousRequestSize(),
            maxElements: $networkConfig->getMaxRequestElements(),
            readTimeout: $networkConfig->getRequestReadTimeout(),
            idleTimeout: $networkConfig->getIdleTimeout(),
        );
    }

    private function makeRequestArrival(Container $container): RequestArrival
    {
        $requestBudget = $container->get(RequestBudget::class);

        return new RequestArrival(
            $container->get(RequestLimits::class),
            new HeldRequests(
                $requestBudget,
                $requestBudget->limitFor(
                    $container->get(ServerListenerOptionsInterface::class)
                        ->getNetworkConfig()
                        ->getMaxHeldRequestSize(),
                ),
            ),
        );
    }

    private function makeEventLogger(Container $container): EventLogger
    {
        $options = $container->get(ServerListenerOptionsInterface::class);

        return new EventLogger(
            $options->getLogger(),
            $options->getEventLogPolicy(),
            $container->get(ConnectionContext::class)->toLogContext(),
        );
    }

    private function makeDecodeFailureResponder(Container $container): DecodeFailureResponder
    {
        return new DecodeFailureResponder(
            $container->get(ServerQueue::class),
            $container->get(ServerAuthorization::class),
            $container->get(EventLogger::class),
        );
    }

    private function makeSessionEndPolicy(Container $container): SessionEndPolicy
    {
        $eventLogger = $container->get(EventLogger::class);

        return new SessionEndPolicy(
            new DisconnectSender(
                $container->get(ServerQueue::class),
                $eventLogger,
            ),
            $eventLogger,
        );
    }

    private function makeAnonymousBind(Container $container): AnonymousBind
    {
        return new AnonymousBind(
            $container->get(ServerQueue::class),
            $container->get(EventLogger::class),
        );
    }

    private function makeResponseWriter(Container $container): ResponseWriter
    {
        $queue = $container->get(ServerQueue::class);

        return new ResponseWriter(
            $queue,
            $container->get(DecodeFailureResponder::class),
            new OutOfSequenceResponder(
                $queue,
                $container->get(EventLogger::class),
            ),
        );
    }

    private function makeConfidentialityMiddleware(Container $container): ConfidentialityMiddleware
    {
        return new ConfidentialityMiddleware(
            $container->get(ServerListenerOptionsInterface::class),
            $container->get(ServerQueue::class),
        );
    }

    private function makeBindMiddleware(Container $container): BindMiddleware
    {
        return new BindMiddleware(
            $container->get(ServerAuthorization::class),
            $container->get(Authenticator::class),
            $container->get(CriticalControlValidator::class),
        );
    }

    private function makeServerProtocolHandler(Container $container): ServerProtocolHandler
    {
        return new ServerProtocolHandler(
            queue: $container->get(ServerQueue::class),
            requestPipeline: $container->get(MiddlewareChain::class),
            sessionEndPolicy: $container->get(SessionEndPolicy::class),
            decodeFailures: $container->get(DecodeFailureResponder::class),
            eventLogger: $container->get(EventLogger::class),
            connectionContext: $container->get(ConnectionContext::class),
        );
    }
}
