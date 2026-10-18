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
 * Whether the driver starts the server itself or targets one that is already running.
 */
enum ServerMode: string
{
    case Spawn = 'spawn';

    case External = 'external';
}
