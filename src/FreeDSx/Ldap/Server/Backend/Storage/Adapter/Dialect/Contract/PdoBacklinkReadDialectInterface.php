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
 * Database-specific SQL for reading the link table backwards
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoBacklinkReadDialectInterface
{
    /**
     * Links naming a contiguous span of targets, with their owners' current DNs.
     *
     * Parameters: [first, last]
     *
     * @param list<string> $names Linked attribute names, pre-validated.
     */
    public function queryBacklinksForRange(array $names): string;

    /**
     * The same, at most limit rows.
     *
     * Parameters: [first, last, limit]
     *
     * @param list<string> $names Linked attribute names, pre-validated.
     */
    public function queryBacklinksForRangeUpTo(array $names): string;

    /**
     * The (target_entry_id, attr_name_lower) pairs in a span named by more than cap links.
     *
     * Parameters: [first, last, cap]
     *
     * @param list<string> $names Linked attribute names, pre-validated.
     */
    public function queryOversizedBacklinks(array $names): string;

    /**
     * A span's back-links apart from $count excluded pairs.
     *
     * Parameters: [first, last, then target_entry_id, attr_name_lower per pair]
     *
     * @param list<string> $names Linked attribute names, pre-validated.
     */
    public function queryBacklinksForRangeExcept(
        array $names,
        int $count,
    ): string;

    /**
     * One target's back-links for one attribute, at most limit rows.
     *
     * Parameters: [target_entry_id, attr_name_lower, limit]
     */
    public function queryBacklinksForAttribute(): string;

    /**
     * The same, starting past the values a slice leaves behind.
     *
     * Parameters: [target_entry_id, attr_name_lower, limit, offset]
     */
    public function queryBacklinksForAttributeFrom(): string;

    /**
     * Which of $count named DNs link to a target under one attribute.
     *
     * Parameters: [target lc_dn, attr_name_lower, then owner lc_dn per name]
     */
    public function queryHeldBacklinkValues(int $count): string;

    /**
     * Any one DN linking to a target under an attribute, for answering whether it is named at all.
     *
     * Parameters: [target lc_dn, attr_name_lower]
     */
    public function queryAnyBacklinkValue(): string;
}
