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

use FreeDSx\Ldap\Server\Config\Storage\PdoDriver;
use PDOException;

/**
 * Reads a driver failure as the configured database means it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PdoErrorFactory
{
    public function __construct(private PdoDriver $driver) {}

    public function of(PDOException $exception): PdoErrorInterface
    {
        $info = DriverErrorInfo::of($exception);

        return match ($this->driver) {
            PdoDriver::Sqlite => new SqliteError($info),
            PdoDriver::Mysql => new MysqlError($info),
        };
    }
}
