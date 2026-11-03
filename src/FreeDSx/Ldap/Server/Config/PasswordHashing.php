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

namespace FreeDSx\Ldap\Server\Config;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;

use function sprintf;

/**
 * The scheme and work factor the server hashes a new password with.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PasswordHashing
{
    private const DEFAULT_BCRYPT_COST = 12;

    private const DEFAULT_ARGON2_MEMORY = 7168;

    private const DEFAULT_ARGON2_PASSES = 5;

    private const DEFAULT_ARGON2_THREADS = 1;

    private const BCRYPT_MIN_COST = 4;

    private const BCRYPT_MAX_COST = 31;

    /**
     * The least memory, in KiB, argon2 accepts for each thread.
     */
    private const ARGON2_MIN_MEMORY_PER_THREAD = 8;

    /**
     * @param int<4, 31> $bcryptCost
     * @param positive-int $argon2Memory
     * @param positive-int $argon2Passes
     * @param positive-int $argon2Threads
     */
    private function __construct(
        private PasswordHashScheme $scheme,
        private int $bcryptCost = self::DEFAULT_BCRYPT_COST,
        private int $argon2Memory = self::DEFAULT_ARGON2_MEMORY,
        private int $argon2Passes = self::DEFAULT_ARGON2_PASSES,
        private int $argon2Threads = self::DEFAULT_ARGON2_THREADS,
    ) {}

    /**
     * Argon2id, its memory in KiB, defaulting to OWASP's 7 MiB and five passes.
     *
     * @param positive-int $memoryKiB
     * @param positive-int $passes
     * @param positive-int $threads
     *
     * @throws InvalidArgumentException when a setting is below what argon2 accepts
     */
    public static function argon2id(
        int $memoryKiB = self::DEFAULT_ARGON2_MEMORY,
        int $passes = self::DEFAULT_ARGON2_PASSES,
        int $threads = self::DEFAULT_ARGON2_THREADS,
    ): self {
        self::atLeast(
            $passes,
            1,
            'argon2 passes',
        );
        self::atLeast(
            $threads,
            1,
            'argon2 threads',
        );
        self::atLeast(
            $memoryKiB,
            self::ARGON2_MIN_MEMORY_PER_THREAD * $threads,
            'argon2 memory in KiB',
        );

        return new self(
            PasswordHashScheme::Argon2,
            argon2Memory: $memoryKiB,
            argon2Passes: $passes,
            argon2Threads: $threads,
        );
    }

    /**
     * Bcrypt, which reads at most the first 72 bytes of a password and none holding a NUL byte.
     *
     * @param int<4, 31> $cost
     *
     * @throws InvalidArgumentException when the cost is outside what bcrypt accepts
     */
    public static function bcrypt(int $cost = self::DEFAULT_BCRYPT_COST): self
    {
        self::atLeast(
            $cost,
            self::BCRYPT_MIN_COST,
            'bcrypt cost',
        );
        self::atMost(
            $cost,
            self::BCRYPT_MAX_COST,
            'bcrypt cost',
        );

        return new self(
            PasswordHashScheme::Bcrypt,
            bcryptCost: $cost,
        );
    }

    /**
     * Salted SHA-1, which is fast to guess offline and suits only clients that need it.
     */
    public static function ssha(): self
    {
        return new self(PasswordHashScheme::Ssha);
    }

    public function getScheme(): PasswordHashScheme
    {
        return $this->scheme;
    }

    /**
     * The bcrypt cost, used when the scheme is bcrypt.
     *
     * @return int<4, 31>
     */
    public function getBcryptCost(): int
    {
        return $this->bcryptCost;
    }

    /**
     * The argon2 memory in KiB, used when the scheme is argon2.
     *
     * @return positive-int
     */
    public function getArgon2Memory(): int
    {
        return $this->argon2Memory;
    }

    /**
     * The argon2 passes over its memory, used when the scheme is argon2.
     *
     * @return positive-int
     */
    public function getArgon2Passes(): int
    {
        return $this->argon2Passes;
    }

    /**
     * The argon2 threads, used when the scheme is argon2.
     *
     * @return positive-int
     */
    public function getArgon2Threads(): int
    {
        return $this->argon2Threads;
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function atLeast(
        int $value,
        int $minimum,
        string $setting,
    ): void {
        if ($value >= $minimum) {
            return;
        }

        throw new InvalidArgumentException(sprintf(
            'The %s must be at least %d.',
            $setting,
            $minimum,
        ));
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function atMost(
        int $value,
        int $maximum,
        string $setting,
    ): void {
        if ($value <= $maximum) {
            return;
        }

        throw new InvalidArgumentException(sprintf(
            'The %s must be at most %d.',
            $setting,
            $maximum,
        ));
    }
}
