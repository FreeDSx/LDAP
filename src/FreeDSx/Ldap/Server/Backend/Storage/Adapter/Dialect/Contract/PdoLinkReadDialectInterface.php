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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\LinkKeys;

/**
 * Database-specific SQL for reading the table linked attribute values are kept in.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoLinkReadDialectInterface
{
    /**
     * Links of the owners the keys cover, with their targets' current DNs. Parameters: [the keys' parameters]
     */
    public function queryLinksFor(LinkKeys $owners): string;

    /**
     * The same, at most limit rows. Parameters: [the keys' parameters, limit]
     */
    public function queryLinksForUpTo(LinkKeys $owners): string;

    /**
     * The (owner_entry_id, attr_name_lower) pairs the keys cover holding more than cap links.
     *
     * Parameters: [the keys' parameters, cap]
     */
    public function queryOversizedLinks(LinkKeys $owners): string;

    /**
     * The covered owners' links apart from $count excluded pairs.
     *
     * Parameters: [the keys' parameters, then owner_entry_id, attr_name_lower per pair]
     */
    public function queryLinksForExcept(
        LinkKeys $owners,
        int $count,
    ): string;

    /**
     * One owner's links for one attribute, at most limit rows. Parameters: [owner_entry_id, attr_name_lower, limit]
     */
    public function queryLinksForAttribute(): string;

    /**
     * The same, starting past the values a slice leaves behind.
     *
     * The offset is deliberate. A range names a position rather than a cursor and there is no id to seek from
     * without keeping the state a stateless range mechanism exists to avoid.
     *
     * Ordered by the target's id, so appending a value never disturbs a slice already read.
     *
     * Parameters: [owner_entry_id, attr_name_lower, limit, offset]
     */
    public function queryLinksForAttributeFrom(): string;

    /**
     * Which of $count named DNs an owner links under one attribute.
     *
     * Parameters: [owner lc_dn, attr_name_lower, then target lc_dn per name]
     */
    public function queryHeldLinkValues(int $count): string;

    /**
     * Any one DN an owner links under an attribute, for answering whether it holds the attribute at all.
     *
     * Parameters: [owner lc_dn, attr_name_lower]
     */
    public function queryAnyLinkValue(): string;
}
