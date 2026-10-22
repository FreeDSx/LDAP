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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error\DriverErrorInfo;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error\SqliteError;
use PDOException;
use PHPUnit\Framework\TestCase;

final class SqliteErrorTest extends TestCase
{
    public function test_a_busy_database_is_retryable(): void
    {
        self::assertTrue($this->errorWithDriverCode(5)->isRetryableConflict());
    }

    public function test_a_locked_table_is_retryable(): void
    {
        self::assertTrue($this->errorWithDriverCode(6)->isRetryableConflict());
    }

    public function test_a_constraint_violation_is_not_retryable(): void
    {
        self::assertFalse($this->errorWithDriverCode(19)->isRetryableConflict());
    }

    public function test_an_exception_without_driver_error_info_is_not_retryable(): void
    {
        $error = new SqliteError(DriverErrorInfo::of(new PDOException('Unable to open database file')));

        self::assertFalse($error->isRetryableConflict());
    }

    public function test_no_failure_is_a_value_too_long_since_the_columns_declare_no_length(): void
    {
        self::assertFalse($this->errorWithDriverCode(1406)->isValueTooLong());
        self::assertFalse($this->errorWithDriverCode(19)->isValueTooLong());
    }

    public function test_a_database_file_that_can_no_longer_be_read_or_opened_is_a_lost_connection(): void
    {
        self::assertTrue($this->errorWithDriverCode(10)->isConnectionLost());
        self::assertTrue($this->errorWithDriverCode(14)->isConnectionLost());
    }

    public function test_a_busy_database_is_not_a_lost_connection(): void
    {
        self::assertFalse($this->errorWithDriverCode(5)->isConnectionLost());
        self::assertFalse($this->errorWithDriverCode(19)->isConnectionLost());
    }

    public function test_a_unique_failure_on_the_dn_is_a_duplicate_dn_only(): void
    {
        $error = $this->errorWithDriverCode(
            19,
            'UNIQUE constraint failed: entries.lc_dn',
        );

        self::assertTrue($error->isDuplicateDn());
        self::assertFalse($error->isDuplicateEntryUuid());
    }

    public function test_a_unique_failure_on_the_uuid_is_a_duplicate_entry_uuid_only(): void
    {
        $error = $this->errorWithDriverCode(
            19,
            'UNIQUE constraint failed: entries.entry_uuid',
        );

        self::assertTrue($error->isDuplicateEntryUuid());
        self::assertFalse($error->isDuplicateDn());
    }

    public function test_another_kind_of_constraint_failure_is_not_a_duplicate(): void
    {
        $error = $this->errorWithDriverCode(
            19,
            'NOT NULL constraint failed: entries.entry_uuid',
        );

        self::assertFalse($error->isDuplicateDn());
        self::assertFalse($error->isDuplicateEntryUuid());
    }

    private function errorWithDriverCode(
        int $driverCode,
        string $driverMessage = 'Database failure.',
    ): SqliteError {
        return new SqliteError(new DriverErrorInfo(
            $driverCode,
            $driverMessage,
        ));
    }
}
