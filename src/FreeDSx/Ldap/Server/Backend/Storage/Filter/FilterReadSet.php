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
 * The attribute types a filter reads, and which removed types have been found to concern them.
 *
 * @internal
 */
class FilterReadSet
{
    /**
     * Bounds the removed types remembered per filter, since stored attribute names are arbitrary.
     */
    public const MAX_REMEMBERED = 256;

    /**
     * @var array<string, bool> Whether removing a lowercased base type can change what the filter reads.
     */
    public array $concerns = [];

    /**
     * @param list<string>|null $types Lowercased base types the filter reads, or null when every removal must be judged.
     */
    public function __construct(public readonly ?array $types) {}
}
