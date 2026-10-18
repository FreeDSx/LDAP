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

namespace Tests\Support\FreeDSx\Ldap\Seed;

/**
 * Where generated seed entries live, matching the DNs the load-test workloads address.
 */
final class SeedDn
{
    public const PEOPLE = 'ou=people,dc=foo,dc=bar';

    public const GROUPS = 'ou=groups,dc=foo,dc=bar';

    public static function person(int $index): string
    {
        return 'cn=seed-' . $index . ',' . self::PEOPLE;
    }

    public static function group(string $cn): string
    {
        return 'cn=' . $cn . ',' . self::GROUPS;
    }
}
