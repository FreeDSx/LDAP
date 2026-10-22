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

namespace Tests\Support\FreeDSx\Ldap\Pdo;

use PDOException;

/**
 * Builds the failure a PDO driver raises, carrying the error info it reports.
 */
final class DriverFailure
{
    public static function of(
        int $driverCode,
        string $driverMessage = 'Database failure.',
        string $sqlState = 'HY000',
    ): PDOException {
        $exception = new PDOException($driverMessage);
        $exception->errorInfo = [
            $sqlState,
            $driverCode,
            $driverMessage,
        ];

        return $exception;
    }
}
