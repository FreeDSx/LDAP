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

use Tests\Support\FreeDSx\Ldap\Seed\SeedProfile;

/**
 * What a spawned server seeds, which is also what the workload may address on an external one.
 */
final readonly class SeedSettings
{
    use AssertsSettingsTrait;

    public const DEFAULT_ENTRIES = 100;

    /**
     * Commonly sized people with the relations real directory entries carry.
     */
    public const DEFAULT_PROFILE = SeedProfile::Person;

    /**
     * @param int $attributes Filler attributes added to each seeded entry.
     * @param int $groupSize Members seeded into each group, drawn from the seeded entries.
     */
    public function __construct(
        public int $entries = self::DEFAULT_ENTRIES,
        public int $attributes = 0,
        public SeedProfile $profile = self::DEFAULT_PROFILE,
        public int $groups = 0,
        public int $groupSize = 0,
    ) {
        self::assertNonNegative(
            'seed-entries',
            $entries,
        );
        self::assertNonNegative(
            'seed-attributes',
            $attributes,
        );
        self::assertNonNegative(
            'seed-groups',
            $groups,
        );
        self::assertNonNegative(
            'seed-group-size',
            $groupSize,
        );
    }
}
