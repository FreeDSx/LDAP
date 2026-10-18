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

namespace FreeDSx\Ldap\Server\Backend\Storage\Filter;

/**
 * What one filter item has learned about the descriptions it is tested against.
 *
 * @internal
 */
class AssertionLeafMemo
{
    /**
     * Bounds the descriptions remembered per item.
     */
    public const MAX_DESCRIPTIONS = 256;

    /**
     * @var array<string, bool> Whether the values stored under a description are tested by the item.
     */
    public array $feeds = [];

    /**
     * How many entries the item has been tested against.
     */
    public int $evaluations = 0;

    /**
     * @param ?string $derivedName The derived attribute the item names, if any.
     * @param bool $keyedByType Whether the item asserts no options, so a stored description is decided by its type alone.
     */
    public function __construct(
        public readonly ?string $derivedName,
        public readonly bool $keyedByType,
    ) {}
}
