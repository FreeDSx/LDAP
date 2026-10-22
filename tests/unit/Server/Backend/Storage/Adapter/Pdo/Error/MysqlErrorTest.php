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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error\MysqlError;
use PDOException;
use PHPUnit\Framework\TestCase;

final class MysqlErrorTest extends TestCase
{
    public function test_a_deadlock_is_retryable(): void
    {
        self::assertTrue($this->errorWithDriverCode(1213)->isRetryableConflict());
    }

    public function test_a_lock_wait_timeout_is_retryable(): void
    {
        self::assertTrue($this->errorWithDriverCode(1205)->isRetryableConflict());
    }

    public function test_an_unrelated_database_error_is_not_retryable(): void
    {
        self::assertFalse($this->errorWithDriverCode(1064)->isRetryableConflict());
    }

    public function test_an_exception_without_driver_error_info_is_not_retryable(): void
    {
        self::assertFalse($this->errorOf(new PDOException('Connection refused'))->isRetryableConflict());
    }

    public function test_a_lost_connection_is_not_retryable(): void
    {
        self::assertFalse($this->errorWithDriverCode(2006)->isRetryableConflict());
        self::assertFalse($this->errorWithDriverCode(2013)->isRetryableConflict());
    }

    public function test_a_value_too_long_for_its_column_is_recognised(): void
    {
        self::assertTrue($this->errorWithDriverCode(1406)->isValueTooLong());
    }

    public function test_an_unrelated_database_error_is_not_a_value_too_long(): void
    {
        self::assertFalse($this->errorWithDriverCode(1062)->isValueTooLong());
        self::assertFalse($this->errorOf(new PDOException('Connection refused'))->isValueTooLong());
    }

    public function test_a_duplicate_on_the_dn_key_is_a_duplicate_dn_only(): void
    {
        $error = $this->errorWithDriverCode(
            1062,
            "Duplicate entry 'cn=a,dc=example,dc=com' for key 'entries.uq_lc_dn'",
        );

        self::assertTrue($error->isDuplicateDn());
        self::assertFalse($error->isDuplicateEntryUuid());
    }

    public function test_a_duplicate_on_the_uuid_key_is_a_duplicate_entry_uuid_only(): void
    {
        $error = $this->errorWithDriverCode(
            1062,
            "Duplicate entry 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d' for key 'entries.uq_entry_uuid'",
        );

        self::assertTrue($error->isDuplicateEntryUuid());
        self::assertFalse($error->isDuplicateDn());
    }

    public function test_a_key_named_without_its_table_is_still_recognised(): void
    {
        $error = $this->errorWithDriverCode(
            1062,
            "Duplicate entry 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d' for key 'uq_entry_uuid'",
        );

        self::assertTrue($error->isDuplicateEntryUuid());
    }

    public function test_a_duplicate_value_naming_the_other_key_does_not_decide_which_key_refused(): void
    {
        $error = $this->errorWithDriverCode(
            1062,
            "Duplicate entry 'cn=uq_entry_uuid\\',dc=example,dc=com' for key 'entries.uq_lc_dn'",
        );

        self::assertTrue($error->isDuplicateDn());
        self::assertFalse($error->isDuplicateEntryUuid());
    }

    public function test_an_unrelated_database_error_is_not_a_duplicate(): void
    {
        $error = $this->errorWithDriverCode(
            1406,
            "Data too long for column 'lc_dn' at row 1",
        );

        self::assertFalse($error->isDuplicateDn());
        self::assertFalse($error->isDuplicateEntryUuid());
    }

    private function errorWithDriverCode(
        int $driverCode,
        string $driverMessage = 'Database failure.',
    ): MysqlError {
        return new MysqlError(new DriverErrorInfo(
            $driverCode,
            $driverMessage,
        ));
    }

    private function errorOf(PDOException $exception): MysqlError
    {
        return new MysqlError(DriverErrorInfo::of($exception));
    }
}
