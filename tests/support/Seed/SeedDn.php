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
 * Where generated seed entries live and the mail domain they use, defaulting to what the load-test workloads address.
 */
final readonly class SeedDn
{
    public const PEOPLE = 'ou=people,dc=foo,dc=bar';

    public const GROUPS = 'ou=groups,dc=foo,dc=bar';

    public const MAIL_DOMAIN = 'foo.bar';

    public function __construct(
        public string $people = self::PEOPLE,
        public string $groups = self::GROUPS,
        public string $mailDomain = self::MAIL_DOMAIN,
    ) {}

    public function person(int $index): string
    {
        return 'cn=seed-' . $index . ',' . $this->people;
    }

    public function group(string $cn): string
    {
        return 'cn=' . $cn . ',' . $this->groups;
    }
}
