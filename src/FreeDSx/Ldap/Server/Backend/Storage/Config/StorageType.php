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

namespace FreeDSx\Ldap\Server\Backend\Storage\Config;

/**
 * The built-in storage backend a StorageConfigInterface selects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum StorageType
{
    case Pdo;

    case Json;

    case InMemory;
}
