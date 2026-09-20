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

use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;

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
}
