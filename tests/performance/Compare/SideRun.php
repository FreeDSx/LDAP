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

use Tests\Performance\FreeDSx\Ldap\Stats\StatsSnapshot;

/**
 * One side's measured run and anything its access control got wrong for the run identity.
 */
final readonly class SideRun
{
    /**
     * @param list<string> $accessProblems Empty when the run identity saw exactly what it should.
     */
    public function __construct(
        public StatsSnapshot $snapshot,
        public array $accessProblems,
    ) {}
}
