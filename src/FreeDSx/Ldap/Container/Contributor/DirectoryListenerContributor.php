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
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Config\Storage\StorageType;

/**
 * A directory server's contribution: its backend is reset per fork and carried, with its storage, across a reload.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class DirectoryListenerContributor implements ListenerContributorInterface
{
    /**
     * @param array<class-string, object> $reloadInstances
     */
    public function __construct(
        private WritableStorageBackend $backend,
        private array $reloadInstances,
        private StorageType $storageType,
    ) {}

    public function forkResettable(): ResettableInterface
    {
        return $this->backend;
    }

    public function supportsMultipleWorkers(): bool
    {
        return $this->storageType->isMultiProcessSafe();
    }

    public function reloadInstances(): array
    {
        return $this->reloadInstances;
    }
}
