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

namespace FreeDSx\Ldap\Container\Provider;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoBackend;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\AllowUserChangeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\HistoryConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\MinAgeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\QualityConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\SafeModifyConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyComponentFactory;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\UniquePolicyTimeFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Subentry\GoverningSubentryResolver;
use FreeDSx\Ldap\Server\Subentry\SubtreeSpecificationEvaluator;
use FreeDSx\Ldap\ServerOptions;

/**
 * Registers the password-policy engine and its write/replica collaborators.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PasswordPolicyContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            PasswordPolicyEngine::class => $this->makePasswordPolicyEngine(...),
            ReplicaPasswordStateStoreInterface::class => $this->makeReplicaPasswordStateStore(...),
            PasswordModifyTargetResolver::class => $this->makePasswordModifyTargetResolver(...),
            PasswordHashService::class => $this->makePasswordHashService(...),
            PasswordPolicyResolver::class => $this->makePasswordPolicyResolver(...),
            PasswordPolicyComponentFactory::class => $this->makePasswordPolicyComponentFactory(...),
        ];
    }

    private function makePasswordPolicyEngine(Container $container): PasswordPolicyEngine
    {
        $options = $container->get(ServerOptions::class);
        $clock = $container->get(ClockInterface::class);

        $chain = new PasswordChangeConstraintChain([
            new AllowUserChangeConstraint(),
            new SafeModifyConstraint(),
            new MinAgeConstraint($clock),
            new QualityConstraint($options->getPasswordConfig()->getQualityChecker()),
            new HistoryConstraint($container->get(PasswordHashService::class)),
        ]);

        return new PasswordPolicyEngine(
            clock: $clock,
            changeConstraints: $chain,
            uniqueTimes: new UniquePolicyTimeFactory(
                $clock,
                $options->getReplicationConfig()->getId(),
            ),
        );
    }

    /**
     * The replica-local password-policy state store, persisted alongside the entries on the storage connection.
     */
    private function makeReplicaPasswordStateStore(Container $container): ReplicaPasswordStateStoreInterface
    {
        $storageConfig = $container->get(ServerOptions::class)->getStorageConfig();

        if (!$storageConfig instanceof PdoConfig) {
            throw new RuntimeException(sprintf(
                'The replica password-policy state store requires PDO storage, but "%s" is configured.',
                $storageConfig::class,
            ));
        }

        return $container->get(PdoBackend::class)->replicaPasswordStateStore;
    }

    private function makePasswordModifyTargetResolver(Container $container): PasswordModifyTargetResolver
    {
        return new PasswordModifyTargetResolver(
            $container->get(ReadBackendInterface::class),
            $container->get(BindNameResolverInterface::class),
        );
    }

    private function makePasswordHashService(Container $container): PasswordHashService
    {
        $config = $container->get(ServerOptions::class)->getPasswordConfig();

        return new PasswordHashService(
            $config->getHashScheme(),
            $config->getHashCost(),
        );
    }

    private function makePasswordPolicyResolver(Container $container): PasswordPolicyResolver
    {
        $options = $container->get(ServerOptions::class);
        $backend = $container->get(ReadBackendInterface::class);

        return new PasswordPolicyResolver(
            $backend,
            $options->getPasswordConfig()->getDefaultPolicyDn(),
            $options->getPasswordConfig()->getPolicy(),
            new GoverningSubentryResolver(
                $backend,
                new SubtreeSpecificationEvaluator($container->get(FilterEvaluatorInterface::class)),
            ),
        );
    }

    private function makePasswordPolicyComponentFactory(Container $container): PasswordPolicyComponentFactory
    {
        return new PasswordPolicyComponentFactory(
            backend: $container->get(ReadBackendInterface::class),
            writeDispatcher: $container->get(WriteOperationDispatcher::class),
            passwordPolicyEngine: $container->get(PasswordPolicyEngine::class),
            policyResolver: $container->get(PasswordPolicyResolver::class),
        );
    }
}
