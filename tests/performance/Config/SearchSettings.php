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
 * How the search operations shape their requests.
 */
final readonly class SearchSettings
{
    use AssertsSettingsTrait;

    public const DEFAULT_SIZE_LIMIT = 500;

    public const DEFAULT_VALUE = 'seed-1';

    /**
     * A sorted search models a bounded display page typically, so give it a realistic limit.
     */
    public const DEFAULT_SORT_SIZE_LIMIT = 50;

    /**
     * @param int $sizeLimit Applied to the list, subtree and paged searches, with 0 meaning unlimited.
     * @param string $value The cn prefix the subtree searches filter on.
     * @param ?string $attributes A CSV list, ALL or 1.1, or null to request every attribute.
     */
    public function __construct(
        public int $sizeLimit = self::DEFAULT_SIZE_LIMIT,
        public string $value = self::DEFAULT_VALUE,
        public int $sortSizeLimit = self::DEFAULT_SORT_SIZE_LIMIT,
        public ?string $attributes = null,
        public bool $attributesOnly = false,
    ) {
        self::assertNonNegative(
            'search-size-limit',
            $sizeLimit,
        );
        self::assertNonNegative(
            'search-sort-size-limit',
            $sortSizeLimit,
        );
    }
}
