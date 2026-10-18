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

namespace Tests\Performance\FreeDSx\Ldap\Compare;

/**
 * One server participating in a comparison run, seeded as one identity and measured as another bound by its ACLs.
 */
final readonly class BenchSide
{
    public function __construct(
        public string $label,
        public string $host,
        public int    $port,
        public string $bindDn,
        public string $bindPassword,
        public string $baseDn,
        public string $runBindDn,
        public string $runBindPassword,
    ) {}
}
