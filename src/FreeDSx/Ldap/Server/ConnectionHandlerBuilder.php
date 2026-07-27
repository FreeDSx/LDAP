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
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\Authorization\ProxiedAuthorizationResolver;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\ExternalMechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderInterface;
use FreeDSx\Ldap\Protocol\Bind\BindInterface;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchange;
use FreeDSx\Ldap\Protocol\Bind\SaslBind;
use FreeDSx\Ldap\Protocol\Bind\SimpleBind;
use FreeDSx\Ldap\Protocol\Factory\HandlerContext;
use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerFactoryMap;
use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerProvider;
use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerProviderInterface;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\Response\MetricsResponseInterceptor;
use FreeDSx\Ldap\Protocol\Queue\Response\PasswordPolicyResponseInterceptor;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerAwareAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordPolicyAwareAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\SaslBindPolicyEnforcer;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Middleware\AssertionMiddleware;
use FreeDSx\Ldap\Server\Middleware\AuthorizationResolutionMiddleware;
use FreeDSx\Ldap\Server\Middleware\BindMiddleware;
use FreeDSx\Ldap\Server\Middleware\CriticalControlMiddleware;
use FreeDSx\Ldap\Server\Middleware\MetricsMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuditMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuthorizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\ResponseWriterMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\HandlerInvoker;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareChain;
use FreeDSx\Ldap\Server\Middleware\ReadOnlyMiddleware;
use FreeDSx\Ldap\Server\Middleware\RequestValidationMiddleware;
use FreeDSx\Ldap\Server\Middleware\ResourceLimitMiddleware;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\PasswordPolicyBindStrategyInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyComponentFactory;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordResetGate;
use FreeDSx\Ldap\Server\Sasl\External\SubjectDnCredentialMapper;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\SaslOptions;
use FreeDSx\Sasl\Sasl;
use FreeDSx\Socket\Socket;

use function in_array;

/**
 * Composes the per-connection protocol handler from container-resolved singletons and fresh connection roots.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ConnectionHandlerBuilder implements ConnectionHandlerBuilderInterface
{
    use ServerConnectionScaffoldingTrait;

    public function __construct(
        private readonly Container $container,
    ) {}

    public function build(
        Socket $socket,
        ConnectionContext $context = new ConnectionContext(),
    ): ServerProtocolHandler {
        $options = $this->serverOptions();
        $handlerFactory = $this->container->get(HandlerFactoryInterface::class);
        $metricsRecorder = $this->container->get(MetricsRecorderInterface::class);

        $eventLogger = $this->makeEventLogger($context);
        $backend = $this->container->get(WritableStorageBackend::class);
        $passwordAuthenticator = $handlerFactory->makePasswordAuthenticator();

        $policyContext = null;
        $interceptors = [];
        if ($options->isPasswordPolicyEnabled()) {
            $policyContext = new PasswordPolicyContext();
            $interceptors[] = new PasswordPolicyResponseInterceptor($policyContext);
            $passwordAuthenticator = $this->decoratePasswordAuthenticator(
                $passwordAuthenticator,
                $backend,
                $policyContext,
                $eventLogger,
            );
        }

        $manager = $options->getManager();
        if ($manager !== null) {
            // Outermost: the manager is recognized before the backend and password policy, so it is lockout-exempt.
            $passwordAuthenticator = new ManagerAwareAuthenticator(
                $passwordAuthenticator,
                $manager,
                $this->container->get(PasswordHashService::class),
            );
        }

        if (!$metricsRecorder instanceof NullMetricsRecorder) {
            $interceptors[] = $this->container->get(MetricsResponseInterceptor::class);
        }

        $serverQueue = $this->makeServerQueue(
            $socket,
            $interceptors,
            $metricsRecorder,
        );

        $authzIdResolver = new AuthzIdResolver(
            $options->getAccessControl(),
            $backend,
            $handlerFactory->makeIdentityResolverChain(),
            $eventLogger,
        );

        $authenticators = [
            new SimpleBind(
                queue: $serverQueue,
                authenticator: $passwordAuthenticator,
                eventLogger: $eventLogger,
            ),
            $this->makeAnonymousBind(
                $serverQueue,
                $eventLogger,
            ),
        ];

        $saslMechanisms = $options->getSaslMechanisms();
        if (!empty($saslMechanisms)) {
            $authenticators[] = $this->makeSaslBind(
                $serverQueue,
                $eventLogger,
                $passwordAuthenticator,
                $authzIdResolver,
                $backend,
                $policyContext,
                $saslMechanisms,
            );
        }

        // Per connection: the bound-token state must not be shared across connections (e.g., coroutines).
        $authorization = new ServerAuthorization($options);

        $dispatchAuthorizer = new DispatchAuthorizer(
            $authorization,
            new PasswordResetGate(),
            new ProxiedAuthorizationResolver($authzIdResolver),
        );

        $handlerProvider = $this->makeProtocolHandlerProvider(
            $serverQueue,
            $eventLogger,
            new RequestHistory(),
            $policyContext,
        );

        return new ServerProtocolHandler(
            queue: $serverQueue,
            requestPipeline: $this->makeRequestPipeline(
                $serverQueue,
                $eventLogger,
                $authorization,
                $authenticators,
                $dispatchAuthorizer,
                $policyContext,
                $backend,
                $handlerProvider,
            ),
            eventLogger: $eventLogger,
            connectionContext: $context,
        );
    }

    protected function serverOptions(): ServerOptions
    {
        return $this->container->get(ServerOptions::class);
    }

    private function decoratePasswordAuthenticator(
        PasswordAuthenticatableInterface $inner,
        LdapBackendInterface $backend,
        PasswordPolicyContext $policyContext,
        EventLogger $eventLogger,
    ): PasswordPolicyAwareAuthenticator {
        return new PasswordPolicyAwareAuthenticator(
            $inner,
            $this->container->get(HandlerFactoryInterface::class)->makeIdentityResolverChain(),
            $backend,
            $this->container->get(PasswordPolicyComponentFactory::class)->makeResolver(),
            $this->makeBindGuard(
                $policyContext,
                $eventLogger,
            ),
        );
    }

    /**
     * @param string[] $saslMechanisms
     */
    private function makeSaslBind(
        ServerQueue $queue,
        EventLogger $eventLogger,
        PasswordAuthenticatableInterface $authenticator,
        AuthzIdResolver $authzIdResolver,
        LdapBackendInterface $backend,
        ?PasswordPolicyContext $policyContext,
        array $saslMechanisms,
    ): SaslBind {
        $responseFactory = new ResponseFactory();

        return new SaslBind(
            queue: $queue,
            exchange: new SaslExchange(
                $queue,
                $responseFactory,
                $this->makeOptionsBuilderFactory(
                    $authenticator,
                    $queue,
                    $saslMechanisms,
                    $authzIdResolver,
                ),
                $authzIdResolver,
            ),
            sasl: new Sasl(new SaslOptions(
                supported: $this->parseKnownMechanisms($saslMechanisms),
            )),
            mechanisms: $saslMechanisms,
            responseFactory: $responseFactory,
            eventLogger: $eventLogger,
            policyEnforcer: $policyContext !== null
                ? $this->makeSaslPolicyEnforcer(
                    $backend,
                    $policyContext,
                    $eventLogger,
                )
                : null,
        );
    }

    private function makeSaslPolicyEnforcer(
        LdapBackendInterface $backend,
        PasswordPolicyContext $policyContext,
        EventLogger $eventLogger,
    ): SaslBindPolicyEnforcer {
        return new SaslBindPolicyEnforcer(
            $this->container->get(HandlerFactoryInterface::class)->makeIdentityResolverChain(),
            $backend,
            $this->container->get(PasswordPolicyComponentFactory::class)->makeResolver(),
            $this->makeBindGuard(
                $policyContext,
                $eventLogger,
            ),
            $policyContext,
        );
    }

    private function makeBindGuard(
        PasswordPolicyContext $policyContext,
        EventLogger $eventLogger,
    ): PasswordPolicyBindGuard {
        return new PasswordPolicyBindGuard(
            $this->container->get(PasswordPolicyEngine::class),
            $this->container->get(PasswordPolicyBindStrategyInterface::class),
            $policyContext,
            $eventLogger,
            $this->container->get(SleeperInterface::class),
        );
    }

    /**
     * @param string[] $saslMechanisms
     */
    private function makeOptionsBuilderFactory(
        PasswordAuthenticatableInterface $authenticator,
        ServerQueue $queue,
        array $saslMechanisms,
        AuthzIdResolver $authzIdResolver,
    ): MechanismOptionsBuilderFactory {
        if (!in_array(ServerOptions::SASL_EXTERNAL, $saslMechanisms, true)) {
            return new MechanismOptionsBuilderFactory($authenticator);
        }

        $options = $this->serverOptions();

        return new MechanismOptionsBuilderFactory(
            $authenticator,
            fn(): MechanismOptionsBuilderInterface => new ExternalMechanismOptionsBuilder(
                $queue,
                $options,
                $options->getExternalCredentialMapper() ?? new SubjectDnCredentialMapper(),
                $authzIdResolver,
            ),
        );
    }

    /**
     * Converts mechanism name strings into known MechanismName values, discarding unrecognised ones.
     *
     * @param string[] $mechanisms
     * @return MechanismName[]
     */
    private function parseKnownMechanisms(array $mechanisms): array
    {
        $known = [];
        foreach ($mechanisms as $name) {
            $mech = MechanismName::tryFrom($name);
            if ($mech !== null) {
                $known[] = $mech;
            }
        }

        return $known;
    }

    private function makeProtocolHandlerProvider(
        ServerQueue $queue,
        EventLogger $eventLogger,
        RequestHistory $requestHistory,
        ?PasswordPolicyContext $policyContext,
    ): ProtocolHandlerProvider {
        return new ProtocolHandlerProvider(
            routeResolver: $this->container->get(ServerProtocolHandlerFactory::class),
            factories: $this->container->get(ProtocolHandlerFactoryMap::class),
            context: new HandlerContext(
                connection: $queue,
                eventLogger: $eventLogger,
                requestHistory: $requestHistory,
                passwordPolicyContext: $policyContext,
            ),
        );
    }

    /**
     * @param BindInterface[] $authenticators
     */
    private function makeRequestPipeline(
        ServerQueue $queue,
        EventLogger $eventLogger,
        ServerAuthorization $authorization,
        array $authenticators,
        DispatchAuthorizer $dispatchAuthorizer,
        ?PasswordPolicyContext $policyContext,
        LdapBackendInterface $backend,
        ProtocolHandlerProviderInterface $handlerProvider,
    ): MiddlewareChain {
        $options = $this->serverOptions();
        $replicaConfig = $options->getReplicaConfig();

        return new MiddlewareChain(
            [
                // First, so it times and records every message (including binds) regardless of outcome.
                $this->container->get(MetricsMiddleware::class),
                // Order matters: AuthorizationResolutionMiddleware injects the token via withToken(), so
                // every middleware after it may rely on tokenOrFail(). Keep token consumers below it.
                new RequestValidationMiddleware(),
                new BindMiddleware(
                    $authorization,
                    new Authenticator($authenticators),
                ),
                new AuthorizationResolutionMiddleware(
                    $dispatchAuthorizer,
                    $policyContext,
                ),
                // The token is resolved at this point, so per-identity limits can be attached.
                $this->container->get(ResourceLimitMiddleware::class),
                // Audits the resolved outcome; sits above the writer so a streamed result's count is final.
                new OperationAuditMiddleware(new OperationAuditor($eventLogger)),
                // The single sink: drains every operation response and renders any thrown failure.
                new ResponseWriterMiddleware(
                    new ResponseWriter($queue),
                    $backend,
                    $options->getAccessControl(),
                ),
                // Only present on a read-only replica; sits below the writer so its referral is drained,
                // and before the ACL loop so a write short-circuits early.
                ...($replicaConfig !== null
                    ? [new ReadOnlyMiddleware($replicaConfig)]
                    : []),
                $this->container->get(CriticalControlMiddleware::class),
                $this->container->get(OperationAuthorizationMiddleware::class),
                $this->container->get(AssertionMiddleware::class),
            ],
            new HandlerInvoker($handlerProvider),
        );
    }
}
