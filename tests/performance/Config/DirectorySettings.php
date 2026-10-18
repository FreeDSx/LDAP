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
 * The identity the workload binds as, and where in the tree it reads and writes.
 */
final readonly class DirectorySettings
{
    /**
     * The write mixes need an identity the harness treats as an administrator.
     */
    public const DEFAULT_BIND_DN = 'cn=admin,dc=foo,dc=bar';

    public const DEFAULT_BIND_PASSWORD = '12345';

    public const DEFAULT_BASE_DN = 'dc=foo,dc=bar';

    public const DEFAULT_WRITE_BASE = 'ou=people,dc=foo,dc=bar';

    /**
     * @param string $baseDn The base the read, equality and subtree searches start from.
     * @param string $writeBase The parent of the seeded entries and of everything the write ops add.
     */
    public function __construct(
        public string $bindDn = self::DEFAULT_BIND_DN,
        public string $bindPassword = self::DEFAULT_BIND_PASSWORD,
        public string $baseDn = self::DEFAULT_BASE_DN,
        public string $writeBase = self::DEFAULT_WRITE_BASE,
    ) {}
}
