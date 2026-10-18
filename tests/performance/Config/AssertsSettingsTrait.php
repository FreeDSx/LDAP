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

namespace Tests\Performance\FreeDSx\Ldap\Config;

use InvalidArgumentException;

/**
 * Range checks for numeric settings, reported against the CLI option that supplies each one.
 */
trait AssertsSettingsTrait
{
    private static function assertPositive(
        string $option,
        int $value,
    ): void {
        if ($value > 0) {
            return;
        }

        throw new InvalidArgumentException("--{$option} must be greater than zero, got {$value}.");
    }

    private static function assertNonNegative(
        string $option,
        int $value,
    ): void {
        if ($value >= 0) {
            return;
        }

        throw new InvalidArgumentException("--{$option} must be zero or greater, got {$value}.");
    }
}
