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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error;

/**
 * A SQLite failure, read from its result code and, for a constraint, the column the message names.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SqliteError implements PdoErrorInterface
{
    /**
     * The database file is locked by another writer.
     */
    private const ERROR_BUSY = 5;

    /**
     * A table in the database is locked, which the busy handler is never invoked for.
     */
    private const ERROR_LOCKED = 6;

    /**
     * A constraint was violated, which the message then names.
     */
    private const ERROR_CONSTRAINT = 19;

    public function __construct(private DriverErrorInfo $info) {}

    /**
     * `busy_timeout` absorbs most contention by waiting, but it still gives up once the timeout is exhausted.
     */
    public function isRetryableConflict(): bool
    {
        return $this->info->hasDriverCode(
            self::ERROR_BUSY,
            self::ERROR_LOCKED,
        );
    }

    public function isDuplicateDn(): bool
    {
        return $this->isUniqueFailureOn('entries.lc_dn');
    }

    public function isDuplicateEntryUuid(): bool
    {
        return $this->isUniqueFailureOn('entries.entry_uuid');
    }

    /**
     * SQLite declares no length on its columns.
     */
    public function isValueTooLong(): bool
    {
        return false;
    }

    /**
     * The constraint code covers every kind of constraint; the message's table and column say which key refused.
     */
    private function isUniqueFailureOn(string $column): bool
    {
        return $this->info->hasDriverCode(self::ERROR_CONSTRAINT)
            && $this->info->driverMessage() === 'UNIQUE constraint failed: ' . $column;
    }
}
