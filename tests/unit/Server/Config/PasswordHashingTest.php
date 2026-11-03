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
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\Config\PasswordHashing;
use PHPUnit\Framework\TestCase;

final class PasswordHashingTest extends TestCase
{
    public function test_argon2id_defaults_to_7_mib_five_passes_and_one_thread(): void
    {
        $hashing = PasswordHashing::argon2id();

        self::assertSame(
            [
                PasswordHashScheme::Argon2,
                7168,
                5,
                1,
            ],
            [
                $hashing->getScheme(),
                $hashing->getArgon2Memory(),
                $hashing->getArgon2Passes(),
                $hashing->getArgon2Threads(),
            ],
        );
    }

    public function test_bcrypt_defaults_to_cost_12(): void
    {
        $hashing = PasswordHashing::bcrypt();

        self::assertSame(
            [
                PasswordHashScheme::Bcrypt,
                12,
            ],
            [
                $hashing->getScheme(),
                $hashing->getBcryptCost(),
            ],
        );
    }

    public function test_ssha_hashes_with_salted_sha1(): void
    {
        self::assertSame(
            PasswordHashScheme::Ssha,
            PasswordHashing::ssha()->getScheme(),
        );
    }

    public function test_the_bounds_argon2id_and_bcrypt_accept_are_allowed(): void
    {
        $argon2 = PasswordHashing::argon2id(
            memoryKiB: 8,
            passes: 1,
            threads: 1,
        );

        self::assertSame(
            [
                8,
                1,
                1,
                4,
                31,
            ],
            [
                $argon2->getArgon2Memory(),
                $argon2->getArgon2Passes(),
                $argon2->getArgon2Threads(),
                PasswordHashing::bcrypt(4)->getBcryptCost(),
                PasswordHashing::bcrypt(31)->getBcryptCost(),
            ],
        );
    }

    public function test_a_bcrypt_cost_below_4_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The bcrypt cost must be at least 4.');

        // @phpstan-ignore argument.type
        PasswordHashing::bcrypt(3);
    }

    public function test_a_bcrypt_cost_above_31_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The bcrypt cost must be at most 31.');

        // @phpstan-ignore argument.type
        PasswordHashing::bcrypt(32);
    }

    public function test_argon2_passes_below_one_are_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The argon2 passes must be at least 1.');

        // @phpstan-ignore argument.type
        PasswordHashing::argon2id(passes: 0);
    }

    public function test_argon2_threads_below_one_are_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The argon2 threads must be at least 1.');

        // @phpstan-ignore argument.type
        PasswordHashing::argon2id(threads: 0);
    }

    public function test_argon2_memory_below_8_kib_per_thread_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The argon2 memory in KiB must be at least 16.');

        PasswordHashing::argon2id(
            memoryKiB: 8,
            threads: 2,
        );
    }
}
