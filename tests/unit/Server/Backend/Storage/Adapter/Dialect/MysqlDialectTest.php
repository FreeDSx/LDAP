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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use PDOException;
use PHPUnit\Framework\TestCase;

final class MysqlDialectTest extends TestCase
{
    private MysqlDialect $subject;

    protected function setUp(): void
    {
        $this->subject = new MysqlDialect();
    }

    public function test_a_deadlock_is_retryable(): void
    {
        self::assertTrue($this->subject->isRetryableConflict($this->exceptionWithDriverCode(1213)));
    }

    public function test_a_lock_wait_timeout_is_retryable(): void
    {
        self::assertTrue($this->subject->isRetryableConflict($this->exceptionWithDriverCode(1205)));
    }

    public function test_an_unrelated_database_error_is_not_retryable(): void
    {
        self::assertFalse($this->subject->isRetryableConflict($this->exceptionWithDriverCode(1064)));
    }

    public function test_an_exception_without_driver_error_info_is_not_retryable(): void
    {
        self::assertFalse($this->subject->isRetryableConflict(new PDOException('Connection refused')));
    }

    public function test_a_lost_connection_is_not_retryable(): void
    {
        self::assertFalse($this->subject->isRetryableConflict($this->exceptionWithDriverCode(2006)));
        self::assertFalse($this->subject->isRetryableConflict($this->exceptionWithDriverCode(2013)));
    }

    public function test_a_value_too_long_for_its_column_is_recognised(): void
    {
        self::assertTrue($this->subject->isValueTooLong($this->exceptionWithDriverCode(1406)));
    }

    public function test_an_unrelated_database_error_is_not_a_value_too_long(): void
    {
        self::assertFalse($this->subject->isValueTooLong($this->exceptionWithDriverCode(1062)));
        self::assertFalse($this->subject->isValueTooLong(new PDOException('Connection refused')));
    }

    public function test_a_duplicate_on_the_dn_key_is_a_duplicate_dn_only(): void
    {
        $exception = $this->exceptionWithDriverCode(
            1062,
            "Duplicate entry 'cn=a,dc=example,dc=com' for key 'entries.uq_lc_dn'",
        );

        self::assertTrue($this->subject->isDuplicateDn($exception));
        self::assertFalse($this->subject->isDuplicateEntryUuid($exception));
    }

    public function test_a_duplicate_on_the_uuid_key_is_a_duplicate_entry_uuid_only(): void
    {
        $exception = $this->exceptionWithDriverCode(
            1062,
            "Duplicate entry 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d' for key 'entries.uq_entry_uuid'",
        );

        self::assertTrue($this->subject->isDuplicateEntryUuid($exception));
        self::assertFalse($this->subject->isDuplicateDn($exception));
    }

    public function test_a_key_named_without_its_table_is_still_recognised(): void
    {
        $exception = $this->exceptionWithDriverCode(
            1062,
            "Duplicate entry 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d' for key 'uq_entry_uuid'",
        );

        self::assertTrue($this->subject->isDuplicateEntryUuid($exception));
    }

    public function test_a_duplicate_value_naming_the_other_key_does_not_decide_which_key_refused(): void
    {
        $exception = $this->exceptionWithDriverCode(
            1062,
            "Duplicate entry 'cn=uq_entry_uuid\\',dc=example,dc=com' for key 'entries.uq_lc_dn'",
        );

        self::assertTrue($this->subject->isDuplicateDn($exception));
        self::assertFalse($this->subject->isDuplicateEntryUuid($exception));
    }

    public function test_an_unrelated_database_error_is_not_a_duplicate(): void
    {
        $exception = $this->exceptionWithDriverCode(
            1406,
            "Data too long for column 'lc_dn' at row 1",
        );

        self::assertFalse($this->subject->isDuplicateDn($exception));
        self::assertFalse($this->subject->isDuplicateEntryUuid($exception));
    }

    private function exceptionWithDriverCode(
        int $driverCode,
        string $message = 'Database failure.',
    ): PDOException {
        $exception = new PDOException('Database failure.');
        $exception->errorInfo = [
            '40001',
            $driverCode,
            $message,
        ];

        return $exception;
    }
}
