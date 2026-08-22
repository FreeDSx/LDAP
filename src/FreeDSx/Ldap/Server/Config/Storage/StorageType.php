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
 * The built-in storage backend a StorageConfigInterface selects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum StorageType
{
    case Pdo;

    case InMemory;

    /**
     * Whether a directory can be served by several processes at once; the config refines it.
     *
     * @see StorageConfigInterface::isMultiProcessSafe()
     */
    public function isMultiProcessSafe(): bool
    {
        return match ($this) {
            self::Pdo => true,
            self::InMemory => false,
        };
    }
}
