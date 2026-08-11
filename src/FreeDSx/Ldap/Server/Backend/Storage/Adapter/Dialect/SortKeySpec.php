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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

/**
 * One resolved sort key: the lowercased attribute, its SQL direction, and how its values order.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SortKeySpec
{
    public function __construct(
        public string $attributeLower,
        public string $direction,
        public bool $numeric = false,
    ) {}
}
