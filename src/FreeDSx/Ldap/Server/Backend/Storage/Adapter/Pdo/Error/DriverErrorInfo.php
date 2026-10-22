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

use PDOException;

use function in_array;
use function is_int;
use function is_string;
use function str_starts_with;

/**
 * The code, message and SQLSTATE a PDO driver reported with a failure.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DriverErrorInfo
{
    /**
     * The SQLSTATE class for a connection exception.
     */
    private const SQLSTATE_CONNECTION_CLASS = '08';

    public function __construct(
        private ?int $driverCode = null,
        private ?string $driverMessage = null,
        private ?string $sqlState = null,
    ) {}

    /**
     * A failure raised without the driver's error info reports none of it.
     */
    public static function of(PDOException $exception): self
    {
        $info = $exception->errorInfo ?? [];

        return new self(
            is_int($info[1] ?? null) ? $info[1] : null,
            is_string($info[2] ?? null) ? $info[2] : null,
            is_string($info[0] ?? null) ? $info[0] : null,
        );
    }

    /**
     * Whether the SQLSTATE is a standard SQL connection exception, whatever the driver.
     */
    public function isConnectionException(): bool
    {
        return $this->sqlState !== null
            && str_starts_with($this->sqlState, self::SQLSTATE_CONNECTION_CLASS);
    }

    public function hasDriverCode(int ...$codes): bool
    {
        return in_array(
            $this->driverCode,
            $codes,
            true,
        );
    }

    public function driverMessage(): ?string
    {
        return $this->driverMessage;
    }
}
