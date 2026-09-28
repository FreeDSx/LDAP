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

namespace FreeDSx\Ldap\Server\Config\Storage;

/**
 * Backs the server with a transient in-memory directory, seeded through the server like any other storage.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class InMemoryStorageConfig implements StorageConfigInterface
{
    public function type(): StorageType
    {
        return StorageType::InMemory;
    }

    public function isMultiProcessSafe(): bool
    {
        return StorageType::InMemory->isMultiProcessSafe();
    }
}
