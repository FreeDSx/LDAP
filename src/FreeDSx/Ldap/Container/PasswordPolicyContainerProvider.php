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

namespace FreeDSx\Ldap\Container;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\ReplicaPasswordStateStoreProviderInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\AllowUserChangeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\HistoryConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\MinAgeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\QualityConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\SafeModifyConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyComponentFactory;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\InMemoryReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\UniquePolicyTimeFactory;
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
            WriteOperationDispatcher::class => $this->makeWriteOperationDispatcher(...),
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
            new QualityConstraint($options->getPasswordQualityChecker()),
            new HistoryConstraint(new PasswordHashService()),
        ]);

        return new PasswordPolicyEngine(
            clock: $clock,
            changeConstraints: $chain,
            uniqueTimes: new UniquePolicyTimeFactory(
                $clock,
                $options->getChangeJournalConfig()->origin,
            ),
        );
    }

    /**
     * The replica-local password-policy state store, persisted by the storage backend when it can, else in memory.
     */
    private function makeReplicaPasswordStateStore(Container $container): ReplicaPasswordStateStoreInterface
    {
        $storage = $container->get(EntryStorageInterface::class);

        return $storage instanceof ReplicaPasswordStateStoreProviderInterface
            ? $storage->replicaPasswordStateStore()
            : new InMemoryReplicaPasswordStateStore();
    }

    private function makePasswordModifyTargetResolver(Container $container): PasswordModifyTargetResolver
    {
        $handlerFactory = $container->get(HandlerFactoryInterface::class);

        return new PasswordModifyTargetResolver(
            $handlerFactory->makeBackend(),
            $handlerFactory->makeIdentityResolverChain(),
        );
    }

    private function makePasswordHashService(Container $container): PasswordHashService
    {
        return new PasswordHashService($container->get(ServerOptions::class)->getPasswordHashScheme());
    }

    private function makeWriteOperationDispatcher(Container $container): WriteOperationDispatcher
    {
        return new WriteOperationDispatcher(
            $container->get(HandlerFactoryInterface::class)->makeBackend(),
        );
    }

    private function makePasswordPolicyComponentFactory(Container $container): PasswordPolicyComponentFactory
    {
        return new PasswordPolicyComponentFactory(
            handlerFactory: $container->get(HandlerFactoryInterface::class),
            options: $container->get(ServerOptions::class),
            writeDispatcher: $container->get(WriteOperationDispatcher::class),
            passwordPolicyEngine: $container->get(PasswordPolicyEngine::class),
        );
    }
}
