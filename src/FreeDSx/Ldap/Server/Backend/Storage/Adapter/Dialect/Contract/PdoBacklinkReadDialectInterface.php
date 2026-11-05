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
 * Database-specific SQL for reading the link table backwards
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoBacklinkReadDialectInterface
{
    /**
     * Links naming the targets the keys cover, with their owners' current DNs.
     *
     * Parameters: [the keys' parameters]
     *
     * @param list<string> $names Linked attribute names, pre-validated.
     */
    public function queryBacklinksFor(
        array $names,
        LinkKeys $targets,
    ): string;

    /**
     * The same, at most limit rows.
     *
     * Parameters: [the keys' parameters, limit]
     *
     * @param list<string> $names Linked attribute names, pre-validated.
     */
    public function queryBacklinksForUpTo(
        array $names,
        LinkKeys $targets,
    ): string;

    /**
     * The (target_entry_id, attr_name_lower) pairs the keys cover named by more than cap links.
     *
     * Parameters: [the keys' parameters, cap]
     *
     * @param list<string> $names Linked attribute names, pre-validated.
     */
    public function queryOversizedBacklinks(
        array $names,
        LinkKeys $targets,
    ): string;

    /**
     * The covered targets' back-links apart from $count excluded pairs.
     *
     * Parameters: [the keys' parameters, then target_entry_id, attr_name_lower per pair]
     *
     * @param list<string> $names Linked attribute names, pre-validated.
     */
    public function queryBacklinksForExcept(
        array $names,
        LinkKeys $targets,
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
