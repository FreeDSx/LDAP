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

namespace Tests\Support\FreeDSx\Ldap;

use const PHP_OS_FAMILY;

/**
 * Skips a test whose subject cannot run on the current operating system.
 */
trait RequiresOperatingSystemTrait
{
    protected function requireUnix(string $reason): void
    {
        if (PHP_OS_FAMILY !== 'Windows') {
            return;
        }

        self::markTestSkipped($reason);
    }
}
