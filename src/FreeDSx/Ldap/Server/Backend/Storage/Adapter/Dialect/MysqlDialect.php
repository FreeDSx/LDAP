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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;
use PDO;
use PDOException;
use PDOStatement;

use function array_chunk;
use function array_merge;
use function array_unique;
use function array_values;
use function count;
use function is_int;
use function is_string;
use function sort;
use function sprintf;

/**
 * MySQL/MariaDB SQL for the PDO storage; requires MySQL 8.0+ or MariaDB 10.6+.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MysqlDialect implements PdoDialectInterface
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
     * Deadlock found when trying to get lock. The transaction has already been rolled back.
     */
    private const ERROR_DEADLOCK = 1213;

    /**
     * Lock wait timeout exceeded.
     */
    private const ERROR_LOCK_WAIT_TIMEOUT = 1205;

    /**
     * Duplicate entry for key.
     */
    private const ERROR_DUPLICATE_ENTRY = 1062;

    /**
     * Data too long for a column.
     */
    private const ERROR_DATA_TOO_LONG = 1406;

    /**
     * Values per locking read.
     */
    private const LOCK_BATCH_SIZE = 500;

    /**
     * InnoDB resolves lock conflicts by failing one transaction, which is then safe to reissue unchanged.
     */
    public function isRetryableConflict(PDOException $exception): bool
    {
        $driverCode = $exception->errorInfo[1] ?? null;

        return $driverCode === self::ERROR_DEADLOCK
            || $driverCode === self::ERROR_LOCK_WAIT_TIMEOUT;
    }

    public function isDuplicateDn(PDOException $exception): bool
    {
        return $this->isDuplicateOnKey(
            $exception,
            'uq_lc_dn',
        );
    }

    public function isDuplicateEntryUuid(PDOException $exception): bool
    {
        return $this->isDuplicateOnKey(
            $exception,
            'uq_entry_uuid',
        );
    }

    public function isValueTooLong(PDOException $exception): bool
    {
        return ($exception->errorInfo[1] ?? null) === self::ERROR_DATA_TOO_LONG;
    }

    /**
     * Sorted and taken through the key's own index, so overlapping batches always lock in the same order.
     *
     * @param list<string|int> $keys
     *
     * @return list<string|int>
     */
    public function lockRowForWrite(
        PDO $pdo,
        LockableTable $table,
        array $keys,
    ): array {
        $keys = array_values(array_unique($keys));
        sort(
            $keys,
            SORT_STRING,
        );
        $statements = [];
        $batches = [];

        foreach (array_chunk($keys, self::LOCK_BATCH_SIZE) as $chunk) {
            $count = count($chunk);
            $statements[$count] ??= $pdo->prepare(sprintf(
                'SELECT %s FROM %s FORCE INDEX (%s) WHERE %s IN (%s) FOR UPDATE',
                $table->keyColumn(),
                $table->value,
                $table->keyIndex(),
                $table->keyColumn(),
                SqlFilterUtility::markers($count),
            ));
            $statements[$count]->execute($chunk);
            $batches[] = $this->lockedKeys($statements[$count]);
        }

        return array_merge(...$batches);
    }

    public function lockRowForReference(
        PDO $pdo,
        LockableTable $table,
        string|int $key,
    ): bool {
        $keyColumn = $table->keyColumn();
        $statement = $pdo->prepare(<<<SQL
            SELECT $keyColumn
            FROM {$table->value}
            WHERE $keyColumn = ?
            FOR SHARE
            SQL);
        $statement->execute([$key]);

        return $statement->fetch() !== false;
    }

    /**
     * What the DN columns hold, which is InnoDB's own ceiling for the unique key over one of them.
     */
    public function maxDnLength(): int
    {
        return 3072;
    }

    protected function charLength(string $column): string
    {
        return "CHAR_LENGTH($column)";
    }

    /**
     * The DN columns are binary, where CHAR_LENGTH and SUBSTR would count bytes rather than the characters PHP passes.
     */
    protected function textOf(string $column): string
    {
        return "CONVERT($column USING utf8mb4)";
    }

    protected function concat(
        string $left,
        string $right,
    ): string {
        return "CONCAT($left, $right)";
    }

    /**
     * The entry table's collation is case-insensitive, so the comparison is taken to bytes to match every other adapter.
     */
    protected function binaryCompare(
        string $left,
        string $right,
    ): string {
        return "CAST($left AS BINARY) = CAST($right AS BINARY)";
    }

    /**
     * Wrapped in a derived table, which MySQL materializes.
     *
     * A subquery is otherwise refused for reading the table the statement is updating.
     */
    protected function scopedSubtreeIds(): string
    {
        $walk = $this->subtreeWalk();

        return <<<SQL
            SELECT scoped.entry_id FROM ($walk) AS scoped
        SQL;
    }

    protected function schemaName(): string
    {
        return 'mysql';
    }

    /**
     * @return list<string|int>
     */
    private function lockedKeys(PDOStatement $statement): array
    {
        $keys = [];

        foreach ($statement->fetchAll(PDO::FETCH_COLUMN) as $key) {
            if (is_string($key) || is_int($key)) {
                $keys[] = $key;
            }
        }

        return $keys;
    }

    /**
     * The message ends with the key name, which MySQL prefixes with the table and MariaDB does not.
     */
    private function isDuplicateOnKey(
        PDOException $exception,
        string $key,
    ): bool {
        $message = $exception->errorInfo[2] ?? null;

        return ($exception->errorInfo[1] ?? null) === self::ERROR_DUPLICATE_ENTRY
            && is_string($message)
            && str_ends_with($message, $key . "'");
    }
}
