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

use function sprintf;

/**
 * The most work verifying a password may ask of the server, which the stored hash and the presented length decide.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PasswordHashLimits
{
    /**
     * The length of a generated password, which the length limit never falls below.
     */
    private const MIN_PASSWORD_LENGTH = 16;

    /**
     * @param positive-int $shaCryptRounds
     * @param positive-int $bcryptCost
     * @param positive-int $extendedDesRounds
     * @param positive-int $argon2Memory
     * @param positive-int $argon2MemoryPasses
     * @param positive-int $argon2Threads
     * @param positive-int $maxPasswordLength
     *
     * @throws InvalidArgumentException when a limit is below its minimum
     */
    public function __construct(
        private int $shaCryptRounds = 1_000_000,
        private int $bcryptCost = 14,
        private int $extendedDesRounds = 1_000_000,
        private int $argon2Memory = 262_144,
        private int $argon2MemoryPasses = 1_048_576,
        private int $argon2Threads = 4,
        private int $maxPasswordLength = 512,
    ) {
        self::atLeast(
            $shaCryptRounds,
            1,
            'shaCryptRounds',
        );
        self::atLeast(
            $bcryptCost,
            1,
            'bcryptCost',
        );
        self::atLeast(
            $extendedDesRounds,
            1,
            'extendedDesRounds',
        );
        self::atLeast(
            $argon2Memory,
            1,
            'argon2Memory',
        );
        self::atLeast(
            $argon2MemoryPasses,
            1,
            'argon2MemoryPasses',
        );
        self::atLeast(
            $argon2Threads,
            1,
            'argon2Threads',
        );
        self::atLeast(
            $maxPasswordLength,
            self::MIN_PASSWORD_LENGTH,
            'maxPasswordLength',
        );
    }

    /**
     * The most rounds a SHA-256 or SHA-512 crypt hash may name.
     *
     * @return positive-int
     */
    public function getShaCryptRounds(): int
    {
        return $this->shaCryptRounds;
    }

    /**
     * @param positive-int $rounds
     *
     * @throws InvalidArgumentException when the limit is below 1
     */
    public function setShaCryptRounds(int $rounds): self
    {
        $this->shaCryptRounds = self::atLeast(
            $rounds,
            1,
            'shaCryptRounds',
        );

        return $this;
    }

    /**
     * The highest bcrypt cost a hash may name.
     *
     * @return positive-int
     */
    public function getBcryptCost(): int
    {
        return $this->bcryptCost;
    }

    /**
     * @param positive-int $cost
     *
     * @throws InvalidArgumentException when the limit is below 1
     */
    public function setBcryptCost(int $cost): self
    {
        $this->bcryptCost = self::atLeast(
            $cost,
            1,
            'bcryptCost',
        );

        return $this;
    }

    /**
     * The most rounds an extended DES crypt hash may name.
     *
     * @return positive-int
     */
    public function getExtendedDesRounds(): int
    {
        return $this->extendedDesRounds;
    }

    /**
     * @param positive-int $rounds
     *
     * @throws InvalidArgumentException when the limit is below 1
     */
    public function setExtendedDesRounds(int $rounds): self
    {
        $this->extendedDesRounds = self::atLeast(
            $rounds,
            1,
            'extendedDesRounds',
        );

        return $this;
    }

    /**
     * The most memory, in KiB, an argon2 hash may name.
     *
     * @return positive-int
     */
    public function getArgon2Memory(): int
    {
        return $this->argon2Memory;
    }

    /**
     * @param positive-int $kibibytes
     *
     * @throws InvalidArgumentException when the limit is below 1
     */
    public function setArgon2Memory(int $kibibytes): self
    {
        $this->argon2Memory = self::atLeast(
            $kibibytes,
            1,
            'argon2Memory',
        );

        return $this;
    }

    /**
     * The most memory times passes, in KiB, an argon2 hash may name.
     *
     * @return positive-int
     */
    public function getArgon2MemoryPasses(): int
    {
        return $this->argon2MemoryPasses;
    }

    /**
     * @param positive-int $kibibytePasses
     *
     * @throws InvalidArgumentException when the limit is below 1
     */
    public function setArgon2MemoryPasses(int $kibibytePasses): self
    {
        $this->argon2MemoryPasses = self::atLeast(
            $kibibytePasses,
            1,
            'argon2MemoryPasses',
        );

        return $this;
    }

    /**
     * The most threads an argon2 hash may name.
     *
     * @return positive-int
     */
    public function getArgon2Threads(): int
    {
        return $this->argon2Threads;
    }

    /**
     * @param positive-int $threads
     *
     * @throws InvalidArgumentException when the limit is below 1
     */
    public function setArgon2Threads(int $threads): self
    {
        $this->argon2Threads = self::atLeast(
            $threads,
            1,
            'argon2Threads',
        );

        return $this;
    }

    /**
     * The longest password, in bytes, the server verifies or accepts as a new cleartext password.
     *
     * @return positive-int
     */
    public function getMaxPasswordLength(): int
    {
        return $this->maxPasswordLength;
    }

    /**
     * @param positive-int $bytes
     *
     * @throws InvalidArgumentException when the limit is below the length of a generated password
     */
    public function setMaxPasswordLength(int $bytes): self
    {
        $this->maxPasswordLength = self::atLeast(
            $bytes,
            self::MIN_PASSWORD_LENGTH,
            'maxPasswordLength',
        );

        return $this;
    }

    /**
     * @param positive-int $minimum
     *
     * @return positive-int
     *
     * @throws InvalidArgumentException
     */
    private static function atLeast(
        int $value,
        int $minimum,
        string $limit,
    ): int {
        if ($value >= $minimum) {
            return $value;
        }

        throw new InvalidArgumentException(sprintf(
            'The "%s" password hash limit must be at least %d.',
            $limit,
            $minimum,
        ));
    }
}
