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

use FreeDSx\Ldap\Server\Utility\Memo\BoundedMemo;

/**
 * The attribute types a filter reads, and which removed types have been found to concern them.
 *
 * @internal
 */
readonly class FilterReadSet
{
    /**
     * @param list<string>|null $types Lowercased base types the filter reads, or null when every removal must be judged.
     * @param list<string> $linked The lowercased linked types among them, whose values an entry need not carry.
     * @param BoundedMemo<string, bool> $concerns Whether removing a lowercased base type changes what the filter reads.
     */
    public function __construct(
        public ?array $types,
        public array $linked,
        public BoundedMemo $concerns,
    ) {}
}
