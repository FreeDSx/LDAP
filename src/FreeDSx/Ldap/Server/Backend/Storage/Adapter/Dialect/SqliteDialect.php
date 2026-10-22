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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoEntryListDialectTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoEntryReadDialectTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoEntryWriteDialectTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoJournalDialectTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoBacklinkReadDialectTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoLinkReadDialectTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoLinkWriteDialectTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoPendingLinkDialectTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoRowLockDialectTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoSchemaTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoSidecarDialectTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql\PdoTransactionDialectTrait;
use PDO;

/**
 * SQLite-specific SQL for the PDO storage.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SqliteDialect implements PdoDialectInterface
{
    use PdoBacklinkReadDialectTrait;
    use PdoEntryListDialectTrait;
    use PdoEntryReadDialectTrait;
    use PdoEntryWriteDialectTrait;
    use PdoJournalDialectTrait;
    use PdoLinkReadDialectTrait;
    use PdoLinkWriteDialectTrait;
    use PdoPendingLinkDialectTrait;
    use PdoRowLockDialectTrait;
    use PdoSchemaTrait;
    use PdoSidecarDialectTrait;
    use PdoTransactionDialectTrait;

    /**
     * `BEGIN IMMEDIATE` acquires the reserved lock up front so concurrent writers wait (honoring `busy_timeout`)
     * instead of racing, which returns SQLITE_BUSY immediately to avoid deadlock.
     */
    public function beginTransaction(PDO $pdo): void
    {
        $pdo->exec('BEGIN IMMEDIATE');
    }

    public function commit(PDO $pdo): void
    {
        $pdo->exec('COMMIT');
    }

    public function rollBack(PDO $pdo): void
    {
        $pdo->exec('ROLLBACK');
    }

    public function maxDnLength(): ?int
    {
        return null;
    }

    public function sortedQuery(
        string $baseSql,
        array $baseParams,
        array $sortKeys,
    ): SortedQuery {
        $terms = [];
        $sortParams = [];

        // RFC 2891 §2.2: NULL is the largest value, so missing entries sort last (ASC) or first (DESC). Native
        // NULLS ordering evaluates the correlated subquery once, so the base query needs no wrapping.
        foreach ($sortKeys as $sortKey) {
            $nulls = $sortKey->direction === 'ASC'
                ? 'NULLS LAST'
                : 'NULLS FIRST';
            $value = $sortKey->numeric
                ? 'CAST(eav.value_lower AS INTEGER)'
                : 'eav.value_lower';
            $terms[] = <<<SQL
                (SELECT MIN({$value})
                 FROM entry_attribute_values eav
                 WHERE eav.owner_entry_id = entry_id
                   AND eav.attr_name_lower = ?) {$sortKey->direction} {$nulls}
                SQL;
            $sortParams[] = $sortKey->attributeLower;
        }

        return new SortedQuery(
            $baseSql . ' ORDER BY ' . implode(', ', $terms),
            array_merge(
                $baseParams,
                $sortParams,
            ),
        );
    }

    protected function schemaName(): string
    {
        return 'sqlite';
    }
}
