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

/**
 * The code and message a PDO driver reported with a failure.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DriverErrorInfo
{
    public function __construct(
        private ?int $driverCode = null,
        private ?string $driverMessage = null,
    ) {}

    /**
     * A failure raised without the driver's error info reports neither.
     */
    public static function of(PDOException $exception): self
    {
        $info = $exception->errorInfo ?? [];

        return new self(
            is_int($info[1] ?? null) ? $info[1] : null,
            is_string($info[2] ?? null) ? $info[2] : null,
        );
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
