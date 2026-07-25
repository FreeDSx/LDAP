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
 * Database-specific SQL for the entry + sidecar tables, transactions, and sort keys.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoEntryDialectInterface
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
     * Take an exclusive lock on the lc_dn row of $table within the current transaction so concurrent writers serialize.
     *
     * @param string $table A fixed internal table identifier, never client input, so implementations may interpolate it.
     */
    public function lockRowForWrite(
        PDO $pdo,
        string $table,
        string $lcDn,
    ): void;

    /**
     * Roll back the current transaction started by beginTransaction().
     */
    public function rollBack(PDO $pdo): void;

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
     * SELECT dn for entries whose parent is not in `entries` (i.e. naming-context roots). No parameters.
     */
    public function queryNamingContexts(): string;

    /**
     * Upsert a single entry. Parameters: [lc_dn, dn, lc_parent_dn, attributes]
     */
    public function queryUpsert(): string;

    /**
     * `DELETE FROM entries WHERE lc_dn = ?`. Parameters: [lc_dn]
     */
    public function queryDelete(): string;

    /**
     * `DELETE FROM entries WHERE lc_dn IN (?, ...)` with $count markers. Parameters: [lc_dn, ...]
     */
    public function queryDeleteIn(int $count): string;

    /**
     * `DELETE FROM entry_attribute_values WHERE entry_lc_dn = ?`. Parameters: [entry_lc_dn]
     */
    public function querySidecarDelete(): string;

    /**
     * The same restricted to $count attribute names. Parameters: [entry_lc_dn, attr_name_lower, ...]
     */
    public function querySidecarDeleteNames(int $count): string;

    /**
     * INSERT prefix for the sidecar; caller appends `(?, ?, ?, ?)` tuples for (entry_lc_dn, attr_name_lower, value_lower, value_original).
     */
    public function querySidecarInsertPrefix(): string;

    /**
     * Maximum DN byte-length allowed by the storage backend, or null if there is no practical limit.
     */
    public function maxDnLength(): ?int;

    /**
     * Rewrites the base entry query with an ORDER BY for the sort keys, NULL/missing values ordered per RFC 2891 §2.2.
     *
     * @param list<string|int> $baseParams
     * @param list<SortKeySpec> $sortKeys
     */
    public function sortedQuery(
        string $baseSql,
        array $baseParams,
        array $sortKeys,
    ): SortedQuery;
}
