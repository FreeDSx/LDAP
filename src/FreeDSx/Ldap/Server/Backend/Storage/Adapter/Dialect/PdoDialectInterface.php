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
     * DDL for the `entries` table. Required columns:
     *   lc_dn         — PK, lowercased DN
     *   dn            — original-case DN
     *   lc_parent_dn  — lowercased parent DN ('' for root)
     *   attributes    — JSON object mapping lowercased attribute names to string-value arrays
     */
    public function ddlCreateTable(): string;

    /**
     * DDL to create an index on lc_parent_dn; return null when already defined inline in ddlCreateTable().
     */
    public function ddlCreateIndex(): ?string;

    /**
     * Existence check: `SELECT 1 FROM entries WHERE lc_dn = ? LIMIT 1`. Parameters: [lc_dn]
     */
    public function queryExists(): string;

    /**
     * `SELECT dn, attributes FROM entries WHERE lc_dn = ?`. Parameters: [lc_dn]
     */
    public function queryFetchEntry(): string;

    /**
     * SELECT dn, attributes with no WHERE clause (returns all entries).
     */
    public function queryFetchAll(): string;

    /**
     * `SELECT dn, attributes FROM entries WHERE lc_parent_dn = ?`. Parameters: [lc_parent_dn]
     */
    public function queryFetchChildren(): string;

    /**
     * Recursive CTE returning (dn, attributes) for the base entry and its descendants; PdoStorage may append `WHERE (filter)`. Parameters: [lc_dn]
     */
    public function querySubtree(): string;

    /**
     * Returns a row when children exist under lc_parent_dn, none otherwise. Parameters: [lc_parent_dn]
     */
    public function queryHasChildren(): string;

    /**
     * Upsert a single entry. Parameters: [lc_dn, dn, lc_parent_dn, attributes]
     */
    public function queryUpsert(): string;

    /**
     * `DELETE FROM entries WHERE lc_dn = ?`. Parameters: [lc_dn]
     */
    public function queryDelete(): string;

    /**
     * Maximum DN byte-length allowed by the storage backend, or null if there is no practical limit.
     */
    public function maxDnLength(): ?int;
}
