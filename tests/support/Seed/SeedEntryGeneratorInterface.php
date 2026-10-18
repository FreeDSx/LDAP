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

use FreeDSx\Ldap\Entry\Entry;

/**
 * Produces the generated entries a test server seeds on top of its fixed content.
 */
interface SeedEntryGeneratorInterface
{
    /**
     * @return iterable<Entry> People first, followed by anything that references them.
     */
    public function generate(int $count): iterable;

    /**
     * Whether the generated entries satisfy the schema, so they can be seeded with validation on.
     */
    public function isSchemaValid(): bool;
}
