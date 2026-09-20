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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract;

/**
 * Database-specific SQL for reading the table linked attribute values are kept in.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoLinkReadDialectInterface
{
    /**
     * Links of a contiguous span of owners with their targets' current DNs. Parameters: [first, last]
     */
    public function queryLinksForRange(): string;

    /**
     * The same, at most limit rows. Parameters: [first, last, limit]
     */
    public function queryLinksForRangeUpTo(): string;

    /**
     * The (owner_entry_id, attr_name_lower) pairs in a span holding more than cap links. Parameters: [first, last, cap]
     */
    public function queryOversizedLinks(): string;

    /**
     * A span's links apart from $count excluded pairs. Parameters: [first, last, then owner_entry_id, attr_name_lower per pair]
     */
    public function queryLinksForRangeExcept(int $count): string;

    /**
     * One owner's links for one attribute, at most limit rows. Parameters: [owner_entry_id, attr_name_lower, limit]
     */
    public function queryLinksForAttribute(): string;
}
