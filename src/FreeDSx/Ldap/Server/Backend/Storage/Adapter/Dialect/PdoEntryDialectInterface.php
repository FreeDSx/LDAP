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
use PDOException;

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
     * Take an exclusive lock on a row of $table within the current transaction so concurrent writers serialize.
     *
     * @param string $table A fixed internal table identifier, never client input, so implementations may interpolate it.
     * @param string $keyColumn A fixed internal column identifier, interpolated for the same reason as $table.
     */
    public function lockRowForWrite(
        PDO $pdo,
        string $table,
        string $keyColumn,
        string|int $key,
    ): void;

    /**
     * Take a shared lock on a row so it cannot be deleted before this transaction ends.
     *
     * @param string $table A fixed internal table identifier, never client input, so implementations may interpolate it.
     * @param string $keyColumn A fixed internal column identifier, interpolated for the same reason as $table.
     */
    public function lockRowForReference(
        PDO $pdo,
        string $table,
        string $keyColumn,
        string|int $key,
    ): bool;

    /**
     * Roll back the current transaction started by beginTransaction().
     */
    public function rollBack(PDO $pdo): void;

    /**
     * Whether the database guarantees the failed transaction applied nothing, so reissuing it cannot double-apply.
     *
     * Being transient is not sufficient: a lost connection may have dropped after the commit was sent, leaving the
     * outcome unknown, so only failures with a defined rollback belong here.
     */
    public function isRetryableConflict(PDOException $exception): bool;

    /**
     * Whether the failure is the unique key on lc_dn refusing a second entry at one DN.
     */
    public function isDuplicateEntry(PDOException $exception): bool;

    /**
     * Existence check: `SELECT 1 FROM entries WHERE lc_dn = ? LIMIT 1`. Parameters: [lc_dn]
     */
    public function queryExists(): string;

    /**
     * `SELECT dn, attributes FROM entries WHERE lc_dn = ?`. Parameters: [lc_dn]
     */
    public function queryFetchEntry(): string;

    /**
     * `SELECT entry_id FROM entries WHERE lc_dn = ?`. Parameters: [lc_dn]
     */
    public function queryEntryId(): string;

    /**
     * SELECT dn, attributes with no WHERE clause (returns all entries).
     *
     * @param bool $withChildFlag Also project whether each row has children, answering hasSubordinates in one pass.
     */
    public function queryFetchAll(bool $withChildFlag = false): string;

    /**
     * `SELECT dn, attributes FROM entries WHERE lc_parent_dn = ?`. Parameters: [lc_parent_dn]
     *
     * @param bool $withChildFlag Also project whether each row has children, answering hasSubordinates in one pass.
     */
    public function queryFetchChildren(bool $withChildFlag = false): string;

    /**
     * Recursive CTE returning (dn, attributes) for the base entry and its descendants; PdoStorage may append `WHERE (filter)`. Parameters: [lc_dn]
     *
     * @param bool $withChildFlag Also project whether each row has children, answering hasSubordinates in one pass.
     */
    public function querySubtree(bool $withChildFlag = false): string;

    /**
     * Parameterless condition restricting $dnColumn to entries that lack, or carry, the subentry object class.
     */
    public function querySubentryCondition(
        string $dnColumn,
        bool $exclude,
    ): string;

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
     * Insert a single entry, failing when the DN is taken.
     *
     * Parameters: [lc_dn, dn, lc_parent_dn, attributes]
     */
    public function queryInsert(): string;

    /**
     * Re-key one entry in place.
     *
     * Parameters: [dn, lc_dn, lc_parent_dn, current lc_dn]
     */
    public function queryRenameEntry(): string;

    /**
     * Re-key every entry beneath a DN, keeping each stored DN's own leading RDNs where it carries the source's stored
     * form. Lengths are counted in characters.
     *
     * Parameters: [from dn length, from dn, from dn length, to dn, from lc_dn length, to lc_dn, from lc_dn length,
     * to lc_dn, from lc_dn length, to lc_dn, from lc_dn]
     */
    public function queryRenameDescendants(): string;

    /**
     * `DELETE FROM entries WHERE lc_dn = ?`. Parameters: [lc_dn]
     */
    public function queryDelete(): string;

    /**
     * `DELETE FROM entries WHERE lc_dn IN (?, ...)` with $count markers. Parameters: [lc_dn, ...]
     */
    public function queryDeleteIn(int $count): string;

    /**
     * `DELETE FROM entry_attribute_values WHERE owner_entry_id = ?`. Parameters: [owner_entry_id]
     */
    public function querySidecarDelete(): string;

    /**
     * The same restricted to $count attribute names. Parameters: [owner_entry_id, attr_name_lower, ...]
     */
    public function querySidecarDeleteNames(int $count): string;

    /**
     * INSERT prefix for the sidecar; caller appends `(?, ?, ?, ?)` tuples for (owner_entry_id, attr_name_lower, value_lower, value_original).
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
