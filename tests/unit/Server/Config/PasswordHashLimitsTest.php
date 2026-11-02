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

namespace Tests\Unit\FreeDSx\Ldap\Server\Config;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Config\PasswordHashLimits;
use PHPUnit\Framework\TestCase;

final class PasswordHashLimitsTest extends TestCase
{
    public function test_a_limit_below_one_is_refused_when_constructed(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "bcryptCost" password hash limit must be at least 1.');

        // @phpstan-ignore argument.type
        new PasswordHashLimits(bcryptCost: 0);
    }

    public function test_a_limit_below_one_is_refused_when_set(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "argon2Threads" password hash limit must be at least 1.');

        // @phpstan-ignore argument.type
        (new PasswordHashLimits())->setArgon2Threads(-1);
    }
}
