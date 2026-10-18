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

namespace Tests\Performance\FreeDSx\Ldap\Config;

/**
 * The storage a spawned server runs on.
 */
enum Backend: string
{
    case Memory = 'memory';

    case Sqlite = 'sqlite';

    case Mysql = 'mysql';
}
