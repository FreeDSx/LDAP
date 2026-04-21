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

use PDO;

/**
 * Provides the database-specific SQL strings used by PdoStorage.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoDialectInterface
{
    /**
     * Begin a write-capable transaction.
     */
    public function beginTransaction(PDO $pdo): void;

    /**
     * Commit the current transaction started by beginTransaction().
     */
    public function commit(PDO $pdo): void;

    /**
     * Roll back the current transaction started by beginTransaction().
     */
    public function rollBack(PDO $pdo): void;


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
     * DDL for the `entry_attribute_values` sidecar index table. Required columns:
     *   entry_lc_dn      — FK to entries.lc_dn ON DELETE CASCADE
     *   attr_name_lower  — lowercased attribute description (stripped of options)
     *   value_lower      — lowercased value, truncated to 255 chars (indexed)
     *   value_original   — original-case full value (not indexed; retained for debugging)
     */
    public function ddlCreateSidecarTable(): string;

    /**
     * DDL statements creating sidecar indexes; empty when indexes are defined inline in ddlCreateSidecarTable().
     *
     * @return list<string>
     */
    public function ddlCreateSidecarIndexes(): array;

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
     * `DELETE FROM entry_attribute_values WHERE entry_lc_dn = ?`. Parameters: [entry_lc_dn]
     */
    public function querySidecarDelete(): string;

    /**
     * INSERT prefix for the sidecar; caller appends `(?, ?, ?, ?)` tuples for (entry_lc_dn, attr_name_lower, value_lower, value_original).
     */
    public function querySidecarInsertPrefix(): string;

    /**
     * Maximum DN byte-length allowed by the storage backend, or null if there is no practical limit.
     */
    public function maxDnLength(): ?int;
}
