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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use PDOException;
use PHPUnit\Framework\TestCase;

final class SqliteDialectTest extends TestCase
{
    private SqliteDialect $subject;

    protected function setUp(): void
    {
        $this->subject = new SqliteDialect();
    }

    public function test_a_busy_database_is_retryable(): void
    {
        self::assertTrue($this->subject->isRetryableConflict($this->exceptionWithDriverCode(5)));
    }

    public function test_a_locked_table_is_retryable(): void
    {
        self::assertTrue($this->subject->isRetryableConflict($this->exceptionWithDriverCode(6)));
    }

    public function test_a_constraint_violation_is_not_retryable(): void
    {
        self::assertFalse($this->subject->isRetryableConflict($this->exceptionWithDriverCode(19)));
    }

    public function test_an_exception_without_driver_error_info_is_not_retryable(): void
    {
        self::assertFalse($this->subject->isRetryableConflict(new PDOException('Unable to open database file')));
    }

    public function test_no_failure_is_a_value_too_long_since_the_columns_declare_no_length(): void
    {
        self::assertFalse($this->subject->isValueTooLong($this->exceptionWithDriverCode(1406)));
        self::assertFalse($this->subject->isValueTooLong($this->exceptionWithDriverCode(19)));
    }

    private function exceptionWithDriverCode(int $driverCode): PDOException
    {
        $exception = new PDOException('Database failure.');
        $exception->errorInfo = [
            'HY000',
            $driverCode,
            'Database failure.',
        ];

        return $exception;
    }
}
