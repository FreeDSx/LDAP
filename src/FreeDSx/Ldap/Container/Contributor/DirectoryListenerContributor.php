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

namespace FreeDSx\Ldap\Container\Contributor;

use FreeDSx\Ldap\Server\AccessControl\AclRuleNames;
use FreeDSx\Ldap\Server\AccessControl\ReloadableAccessControl;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * A directory server's contribution: whatever it holds open is dropped per fork and carried across a reload.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class DirectoryListenerContributor implements ListenerContributorInterface
{
    /**
     * @param ResettableInterface $resettable Dropped per fork, so no child keeps a connection opened before it.
     * @param array<class-string, object> $reloadInstances
     */
    public function __construct(
        private ResettableInterface $resettable,
        private array $reloadInstances,
        private StorageConfigInterface $storageConfig,
        private ReloadableAccessControl $accessControl,
        private AclRuleNames $aclRuleNames,
    ) {}

    public function forkResettable(): ResettableInterface
    {
        return $this->resettable;
    }

    public function supportsMultipleWorkers(): bool
    {
        return $this->storageConfig->isMultiProcessSafe();
    }

    public function reloadInstances(): array
    {
        return $this->reloadInstances;
    }

    public function applyReload(ServerListenerOptionsInterface $reloaded): void
    {
        if (!$reloaded instanceof ServerOptions) {
            return;
        }

        $this->accessControl->replace(new RuleBasedAccessControl(
            $this->aclRuleNames->canonicalize($reloaded->getAclRules()),
        ));
    }
}
