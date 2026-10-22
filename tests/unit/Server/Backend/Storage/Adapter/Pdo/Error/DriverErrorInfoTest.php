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
use PDOException;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\DriverFailure;

final class DriverErrorInfoTest extends TestCase
{
    public function test_it_reads_the_code_and_message_the_driver_reported(): void
    {
        $info = DriverErrorInfo::of(DriverFailure::of(
            1062,
            "Duplicate entry 'a' for key 'uq_lc_dn'",
        ));

        self::assertTrue($info->hasDriverCode(1062));
        self::assertSame(
            "Duplicate entry 'a' for key 'uq_lc_dn'",
            $info->driverMessage(),
        );
    }

    public function test_a_failure_without_driver_error_info_reports_neither(): void
    {
        $info = DriverErrorInfo::of(new PDOException('Connection refused'));

        self::assertFalse($info->hasDriverCode(0));
        self::assertNull($info->driverMessage());
    }

    public function test_it_matches_any_of_the_codes_asked_about(): void
    {
        $info = new DriverErrorInfo(1205);

        self::assertTrue($info->hasDriverCode(
            1213,
            1205,
        ));
        self::assertFalse($info->hasDriverCode(1213));
    }
}
