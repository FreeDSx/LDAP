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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;

/**
 * Five-attribute people that exist to be addressed by the workloads rather than to resemble directory content.
 */
final readonly class MinimalSeedEntries implements SeedEntryGeneratorInterface
{
    use FillerAttributesTrait;

    public function __construct(private int $fillerAttributes = 0) {}

    public function generate(int $count): iterable
    {
        for ($i = 1; $i <= $count; $i++) {
            yield new Entry(
                new Dn(SeedDn::person($i)),
                new Attribute(
                    'cn',
                    "seed-{$i}",
                ),
                new Attribute(
                    'objectClass',
                    'inetOrgPerson',
                    'extensibleObject',
                ),
                new Attribute(
                    'sn',
                    'Seeded',
                ),
                new Attribute(
                    'mail',
                    "seed-{$i}@foo.bar",
                ),
                new Attribute(
                    'uidNumber',
                    (string) (1000 + $i),
                ),
                ...$this->fillers(
                    $i,
                    $this->fillerAttributes,
                ),
            );
        }
    }

    public function isSchemaValid(): bool
    {
        return false;
    }
}
