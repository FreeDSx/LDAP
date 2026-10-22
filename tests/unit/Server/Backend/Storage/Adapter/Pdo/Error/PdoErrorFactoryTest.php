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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error\MysqlError;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error\PdoErrorFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error\SqliteError;
use FreeDSx\Ldap\Server\Config\Storage\PdoDriver;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\DriverFailure;

final class PdoErrorFactoryTest extends TestCase
{
    public function test_a_sqlite_failure_is_read_as_sqlite_means_it(): void
    {
        $error = (new PdoErrorFactory(PdoDriver::Sqlite))->of(DriverFailure::of(5));

        self::assertInstanceOf(
            SqliteError::class,
            $error,
        );
        self::assertTrue($error->isRetryableConflict());
    }

    public function test_a_mysql_failure_is_read_as_mysql_means_it(): void
    {
        $error = (new PdoErrorFactory(PdoDriver::Mysql))->of(DriverFailure::of(1213));

        self::assertInstanceOf(
            MysqlError::class,
            $error,
        );
        self::assertTrue($error->isRetryableConflict());
    }
}
