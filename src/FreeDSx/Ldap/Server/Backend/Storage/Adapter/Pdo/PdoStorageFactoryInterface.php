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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;

/**
 * Constructs a configured PdoStorage for a specific database driver (e.g. SqliteStorage::forPcntl('/path/to/db.sqlite')).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoStorageFactoryInterface
{
    public function create(): PdoStorage;
}
