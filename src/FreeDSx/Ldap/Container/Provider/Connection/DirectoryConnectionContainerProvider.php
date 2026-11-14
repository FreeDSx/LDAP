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

use Closure;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Container\Provider\ContainerProviderInterface;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\Authorization\ProxiedAuthorizationResolver;
use FreeDSx\Ldap\Protocol\Bind\AnonymousBind;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\ExternalMechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderInterface;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchange;
use FreeDSx\Ldap\Protocol\Bind\SaslBind;
use FreeDSx\Ldap\Protocol\Bind\SimpleBind;
use FreeDSx\Ldap\Protocol\DecodeFailureResponder;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\Factory\HandlerContext;
use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerFactoryMap;
use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerProvider;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\Budget\HeldResponses;
use FreeDSx\Ldap\Protocol\Queue\ReadAheadBuffer;
use FreeDSx\Ldap\Protocol\Queue\RequestArrival;
use FreeDSx\Ldap\Protocol\Queue\Response\MetricsResponseInterceptor;
use FreeDSx\Ldap\Protocol\Queue\Response\PasswordPolicyResponseInterceptor;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseInterceptor;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Schema\AttributeTypeSpelling;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\MatchedDnFilter;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerAwareAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordPolicyAwareAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\SaslBindPolicyEnforcer;
use FreeDSx\Ldap\Server\Backend\Auth\SubjectDnCredentialMapper;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Middleware\AliasDereferenceMiddleware;
use FreeDSx\Ldap\Server\Middleware\AssertionMiddleware;
use FreeDSx\Ldap\Server\Middleware\AttributeTypeCanonicalizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\AuthorizationResolutionMiddleware;
use FreeDSx\Ldap\Server\Middleware\BindMiddleware;
use FreeDSx\Ldap\Server\Middleware\ConfidentialityMiddleware;
use FreeDSx\Ldap\Server\Middleware\CriticalControlMiddleware;
use FreeDSx\Ldap\Server\Middleware\CriticalControlValidator;
use FreeDSx\Ldap\Server\Middleware\MetricsMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuditMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuthorizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\PasswordPolicyRequestMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\HandlerInvoker;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareChain;
use FreeDSx\Ldap\Server\Middleware\ReadOnlyMiddleware;
use FreeDSx\Ldap\Server\Middleware\RequestValidationMiddleware;
use FreeDSx\Ldap\Server\Middleware\ResourceLimitMiddleware;
use FreeDSx\Ldap\Server\Middleware\ResponseWriterMiddleware;
use FreeDSx\Ldap\Server\Middleware\TargetDnSyntaxMiddleware;
use FreeDSx\Ldap\Server\Middleware\WithheldAttributeMiddleware;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\PasswordPolicyBindStrategyInterface;
use FreeDSx\Ldap\Server\Paging\PagingSessions;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordResetGate;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\SaslOptions;
use FreeDSx\Sasl\Sasl;
use FreeDSx\Socket\Socket;

use function in_array;

/**
 * Registers the connection-scoped services that compose a directory server's protocol handler.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DirectoryConnectionContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            ServerQueue::class => $this->makeServerQueue(...),
            PasswordPolicyContext::class => static fn(): PasswordPolicyContext => new PasswordPolicyContext(),
            PasswordPolicyBindGuard::class => $this->makePasswordPolicyBindGuard(...),
            PasswordPolicyAwareAuthenticator::class => $this->makePasswordPolicyAwareAuthenticator(...),
            ManagerAwareAuthenticator::class => $this->makeManagerAwareAuthenticator(...),
            AuthzIdResolver::class => $this->makeAuthzIdResolver(...),
            SimpleBind::class => $this->makeSimpleBind(...),
            SaslBindPolicyEnforcer::class => $this->makeSaslBindPolicyEnforcer(...),
            MechanismOptionsBuilderFactory::class => $this->makeMechanismOptionsBuilderFactory(...),
            SaslExchange::class => $this->makeSaslExchange(...),
            SaslBind::class => $this->makeSaslBind(...),
            Authenticator::class => $this->makeAuthenticator(...),
            DispatchAuthorizer::class => $this->makeDispatchAuthorizer(...),
            HandlerContext::class => $this->makeHandlerContext(...),
            ProtocolHandlerProvider::class => $this->makeProtocolHandlerProvider(...),
            PasswordPolicyRequestMiddleware::class => static fn(Container $container): PasswordPolicyRequestMiddleware => new PasswordPolicyRequestMiddleware(
                $container->get(PasswordPolicyContext::class),
            ),
            AuthorizationResolutionMiddleware::class => $this->makeAuthorizationResolutionMiddleware(...),
            OperationAuditMiddleware::class => static fn(Container $container): OperationAuditMiddleware => new OperationAuditMiddleware(
                new OperationAuditor($container->get(EventLogger::class)),
            ),
            ResponseWriterMiddleware::class => $this->makeResponseWriterMiddleware(...),
            MiddlewareChain::class => $this->makeMiddlewareChain(...),
        ];
    }

    private function makeServerQueue(Container $container): ServerQueue
    {
        $metricsRecorder = $container->get(MetricsRecorderInterface::class);

        return new ServerQueue(
            socket: $container->get(Socket::class),
            messageDecoder: $container->get(RequestMessageDecoder::class),
            arrival: $container->get(RequestArrival::class),
            interceptors: $this->makeResponseInterceptors(
                $container,
                $metricsRecorder,
            ),
            metricsRecorder: $metricsRecorder,
            readAhead: new ReadAheadBuffer(),
        );
    }

    /**
     * @return ResponseInterceptor[] applied to every outgoing response, in order.
     */
    private function makeResponseInterceptors(
        Container $container,
        MetricsRecorderInterface $metricsRecorder,
    ): array {
        // Always composed: policy may come from a DIT entry that appears after the server starts.
        $interceptors = [new PasswordPolicyResponseInterceptor($container->get(PasswordPolicyContext::class))];

        if (!$metricsRecorder instanceof NullMetricsRecorder) {
            $interceptors[] = $container->get(MetricsResponseInterceptor::class);
        }

        return $interceptors;
    }

    private function makePasswordPolicyBindGuard(Container $container): PasswordPolicyBindGuard
    {
        return new PasswordPolicyBindGuard(
            $container->get(PasswordPolicyEngine::class),
            $container->get(PasswordPolicyBindStrategyInterface::class),
            $container->get(PasswordPolicyContext::class),
            $container->get(EventLogger::class),
            $container->get(SleeperInterface::class),
        );
    }

    private function makePasswordPolicyAwareAuthenticator(Container $container): PasswordPolicyAwareAuthenticator
    {
        return new PasswordPolicyAwareAuthenticator(
            $container->get(PasswordAuthenticatableInterface::class),
            $container->get(BindNameResolverInterface::class),
            $container->get(ReadBackendInterface::class),
            $container->get(PasswordPolicyResolver::class),
            $container->get(PasswordPolicyBindGuard::class),
        );
    }

    private function makeManagerAwareAuthenticator(Container $container): ManagerAwareAuthenticator
    {
        return new ManagerAwareAuthenticator(
            $container->get(PasswordPolicyAwareAuthenticator::class),
            $container->get(ServerOptions::class)->getManager()
                ?? throw new RuntimeException('A manager-aware authenticator requires a configured manager.'),
            $container->get(PasswordHashService::class),
        );
    }

    /**
     * The authenticator a bind checks a password against.
     */
    private function bindAuthenticator(Container $container): PasswordAuthenticatableInterface
    {
        if ($container->get(ServerOptions::class)->getManager() === null) {
            return $container->get(PasswordPolicyAwareAuthenticator::class);
        }

        // Outermost: the manager is recognized before the backend and password policy and is exempt from lockout.
        return $container->get(ManagerAwareAuthenticator::class);
    }

    private function makeAuthzIdResolver(Container $container): AuthzIdResolver
    {
        return new AuthzIdResolver(
            $container->get(AccessControlInterface::class),
            $container->get(ReadBackendInterface::class),
            $container->get(BindNameResolverInterface::class),
            $container->get(AttributeTypeSpelling::class),
            $container->get(EventLogger::class),
        );
    }

    private function makeSimpleBind(Container $container): SimpleBind
    {
        return new SimpleBind(
            queue: $container->get(ServerQueue::class),
            authenticator: $this->bindAuthenticator($container),
            eventLogger: $container->get(EventLogger::class),
        );
    }

    private function makeSaslBindPolicyEnforcer(Container $container): SaslBindPolicyEnforcer
    {
        return new SaslBindPolicyEnforcer(
            $container->get(BindNameResolverInterface::class),
            $container->get(ReadBackendInterface::class),
            $container->get(PasswordPolicyResolver::class),
            $container->get(PasswordPolicyBindGuard::class),
            $container->get(PasswordPolicyContext::class),
        );
    }

    private function makeMechanismOptionsBuilderFactory(Container $container): MechanismOptionsBuilderFactory
    {
        $authenticator = $this->bindAuthenticator($container);
        $hashService = $container->get(PasswordHashService::class);

        if (!in_array(ServerOptions::SASL_EXTERNAL, $container->get(ServerOptions::class)->getSaslMechanisms(), true)) {
            return new MechanismOptionsBuilderFactory(
                $authenticator,
                $hashService,
            );
        }

        return new MechanismOptionsBuilderFactory(
            $authenticator,
            $hashService,
            $this->makeExternalOptionsBuilderFactory($container),
        );
    }

    /**
     * @return Closure(): MechanismOptionsBuilderInterface
     */
    private function makeExternalOptionsBuilderFactory(Container $container): Closure
    {
        $options = $container->get(ServerOptions::class);
        $queue = $container->get(ServerQueue::class);
        $authzIdResolver = $container->get(AuthzIdResolver::class);

        return static fn(): MechanismOptionsBuilderInterface => new ExternalMechanismOptionsBuilder(
            $queue,
            $options,
            $options->getExternalCredentialMapper() ?? new SubjectDnCredentialMapper(),
            $authzIdResolver,
        );
    }

    private function makeSaslExchange(Container $container): SaslExchange
    {
        return new SaslExchange(
            $container->get(ServerQueue::class),
            $container->get(DecodeFailureResponder::class),
            new ResponseFactory(),
            $container->get(MechanismOptionsBuilderFactory::class),
            $container->get(AuthzIdResolver::class),
            $container->get(CriticalControlValidator::class),
            $container->get(PasswordPolicyContext::class),
        );
    }

    private function makeSaslBind(Container $container): SaslBind
    {
        $mechanisms = $container->get(ServerOptions::class)->getSaslMechanisms();

        return new SaslBind(
            queue: $container->get(ServerQueue::class),
            exchange: $container->get(SaslExchange::class),
            sasl: new Sasl(new SaslOptions(supported: $this->parseKnownMechanisms($mechanisms))),
            mechanisms: $mechanisms,
            eventLogger: $container->get(EventLogger::class),
            policyEnforcer: $container->get(SaslBindPolicyEnforcer::class),
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

    private function makeAuthenticator(Container $container): Authenticator
    {
        $authenticators = [
            $container->get(SimpleBind::class),
            $container->get(AnonymousBind::class),
        ];

        if ($container->get(ServerOptions::class)->getSaslMechanisms() !== []) {
            $authenticators[] = $container->get(SaslBind::class);
        }

        return new Authenticator(
            $authenticators,
            $container->get(ServerQueue::class),
        );
    }

    private function makeDispatchAuthorizer(Container $container): DispatchAuthorizer
    {
        return new DispatchAuthorizer(
            $container->get(ServerAuthorization::class),
            new PasswordResetGate(),
            new ProxiedAuthorizationResolver($container->get(AuthzIdResolver::class)),
        );
    }

    private function makeHandlerContext(Container $container): HandlerContext
    {
        return new HandlerContext(
            connection: $container->get(ServerQueue::class),
            eventLogger: $container->get(EventLogger::class),
            pagingSessions: new PagingSessions(),
            heldResponses: $container->get(HeldResponses::class),
            passwordPolicyContext: $container->get(PasswordPolicyContext::class),
        );
    }

    private function makeProtocolHandlerProvider(Container $container): ProtocolHandlerProvider
    {
        return new ProtocolHandlerProvider(
            routeResolver: $container->get(ServerProtocolHandlerFactory::class),
            factories: $container->get(ProtocolHandlerFactoryMap::class),
            context: $container->get(HandlerContext::class),
        );
    }

    private function makeAuthorizationResolutionMiddleware(Container $container): AuthorizationResolutionMiddleware
    {
        return new AuthorizationResolutionMiddleware(
            $container->get(DispatchAuthorizer::class),
            $container->get(PasswordPolicyContext::class),
        );
    }

    private function makeResponseWriterMiddleware(Container $container): ResponseWriterMiddleware
    {
        return new ResponseWriterMiddleware(
            $container->get(ResponseWriter::class),
            $container->get(MatchedDnFilter::class),
        );
    }

    private function makeMiddlewareChain(Container $container): MiddlewareChain
    {
        $isReplica = $container->get(ServerOptions::class)->getConsumerConfig() !== null;

        return new MiddlewareChain(
            [
                // Outermost: times and records every message, binds included, whatever the outcome.
                $container->get(MetricsMiddleware::class),
                $container->get(RequestValidationMiddleware::class),
                // Settles each attribute type's spelling before any later step reads a DN or attribute name.
                $container->get(AttributeTypeCanonicalizationMiddleware::class),
                // Refuses a credential sent without confidentiality before the bind reads it.
                $container->get(ConfidentialityMiddleware::class),
                // Bind and password-change refusals answer outside this pipeline and are checked ahead of the bind.
                $container->get(PasswordPolicyRequestMiddleware::class),
                $container->get(BindMiddleware::class),
                // Resolves the token that every middleware below this one relies on.
                $container->get(AuthorizationResolutionMiddleware::class),
                // Attaches the per-identity limits once the token is resolved.
                $container->get(ResourceLimitMiddleware::class),
                // Audits from above the writer, where a streamed result's count is final.
                $container->get(OperationAuditMiddleware::class),
                // The single sink: drains every operation response and renders any thrown failure.
                $container->get(ResponseWriterMiddleware::class),
                // Ahead of the access check to give every identity the same answer for a DN the grammar rejects.
                $container->get(TargetDnSyntaxMiddleware::class),
                // Replica only: drains its referral through the writer and refuses a write before the access checks.
                ...($isReplica
                    ? [$container->get(ReadOnlyMiddleware::class)]
                    : []),
                $container->get(CriticalControlMiddleware::class),
                // Above the gate to authorize a base reached through an alias as the entry it resolves to.
                $container->get(AliasDereferenceMiddleware::class),
                $container->get(OperationAuthorizationMiddleware::class),
                // Below the gate to keep an assertion the identity cannot satisfy away from storage.
                $container->get(WithheldAttributeMiddleware::class),
                $container->get(AssertionMiddleware::class),
            ],
            new HandlerInvoker($container->get(ProtocolHandlerProvider::class)),
        );
    }
}
