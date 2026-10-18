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

use function array_map;

/**
 * The shape of the generated entries a test server seeds.
 */
enum SeedProfile: string
{
    case Minimal = 'minimal';

    case Person = 'person';

    /**
     * @return list<string>
     */
    public static function values(): array
    {
        return array_map(
            static fn(self $profile): string => $profile->value,
            self::cases(),
        );
    }

    public function generator(int $fillerAttributes): SeedEntryGeneratorInterface
    {
        return match ($this) {
            self::Minimal => new MinimalSeedEntries($fillerAttributes),
            self::Person => new PersonSeedEntries($fillerAttributes),
        };
    }
}
