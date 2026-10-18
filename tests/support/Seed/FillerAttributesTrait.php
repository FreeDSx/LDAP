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

/**
 * Distinct option subtypes of a defined, non-filtered, non-indexed base type that widen the return path.
 */
trait FillerAttributesTrait
{
    /**
     * @return list<Attribute>
     */
    private function fillers(
        int $index,
        int $count,
    ): array {
        $fillers = [];

        for ($k = 1; $k <= $count; $k++) {
            $fillers[] = new Attribute(
                "initials;filler-{$k}",
                "filler-{$index}-{$k}",
            );
        }

        return $fillers;
    }
}
