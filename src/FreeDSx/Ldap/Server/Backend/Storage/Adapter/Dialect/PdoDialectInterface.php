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
 * Provides the database-specific SQL strings used by PdoStorage.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoDialectInterface
{
    /**
     * DDL to create the entries table if it does not already exist.
     *
     * Required columns:
     *   lc_dn         — primary key, lowercased DN string
     *   dn            — original-case DN string
     *   lc_parent_dn  — lowercased parent DN string (empty string for root entries)
     *   attributes    — JSON object mapping lowercased attribute names to string-value arrays
     */
    public function ddlCreateTable(): string;

    /**
     * DDL to create an index on lc_parent_dn if it does not already exist.
     *
     * Return null if the index is already defined inline in ddlCreateTable()
     */
    public function ddlCreateIndex(): ?string;

    /**
     * SELECT 1 WHERE lc_dn = ? LIMIT 1
     *
     * Lightweight existence check without fetching attributes.
     *
     * Parameters: [lc_dn]
     */
    public function queryExists(): string;

    /**
     * SELECT dn, attributes WHERE lc_dn = ?
     *
     * Parameters: [lc_dn]
     */
    public function queryFetchEntry(): string;

    /**
     * SELECT dn, attributes with no WHERE clause (returns all entries).
     */
    public function queryFetchAll(): string;

    /**
     * SELECT dn, attributes WHERE lc_parent_dn = ?
     *
     * Parameters: [lc_parent_dn]
     */
    public function queryFetchChildren(): string;

    /**
     * Recursive CTE that returns the base entry and all its descendants.
     *
     * The outer SELECT returns (dn, attributes) from the CTE result set.
     * PdoStorage appends `WHERE (filter)` when a translated filter is available.
     *
     * Parameters: [lc_dn]
     */
    public function querySubtree(): string;

    /**
     * Returns at least one row when children exist under lc_parent_dn, zero rows otherwise.
     *
     * Parameters: [lc_parent_dn]
     */
    public function queryHasChildren(): string;

    /**
     * INSERT or UPDATE (upsert) a single entry.
     *
     * Parameters: [lc_dn, dn, lc_parent_dn, attributes]
     */
    public function queryUpsert(): string;

    /**
     * DELETE FROM entries WHERE lc_dn = ?
     *
     * Parameters: [lc_dn]
     */
    public function queryDelete(): string;

    /**
     * Maximum DN byte-length allowed by the storage backend, or null if there is no practical limit.
     */
    public function maxDnLength(): ?int;
}
