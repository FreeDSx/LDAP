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
 * The most work a stored password hash may ask of the server, since verifying it costs what its own parameters say.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PasswordHashLimits
{
    /**
     * @param positive-int $shaCryptRounds
     * @param positive-int $bcryptCost
     * @param positive-int $extendedDesRounds
     * @param positive-int $argon2Memory
     * @param positive-int $argon2MemoryPasses
     * @param positive-int $argon2Threads
     *
     * @throws InvalidArgumentException when a limit is below 1
     */
    public function __construct(
        private int $shaCryptRounds = 1_000_000,
        private int $bcryptCost = 14,
        private int $extendedDesRounds = 1_000_000,
        private int $argon2Memory = 262_144,
        private int $argon2MemoryPasses = 1_048_576,
        private int $argon2Threads = 4,
    ) {
        self::atLeastOne($shaCryptRounds, 'shaCryptRounds');
        self::atLeastOne($bcryptCost, 'bcryptCost');
        self::atLeastOne($extendedDesRounds, 'extendedDesRounds');
        self::atLeastOne($argon2Memory, 'argon2Memory');
        self::atLeastOne($argon2MemoryPasses, 'argon2MemoryPasses');
        self::atLeastOne($argon2Threads, 'argon2Threads');
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
        $this->shaCryptRounds = self::atLeastOne($rounds, 'shaCryptRounds');

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
        $this->bcryptCost = self::atLeastOne($cost, 'bcryptCost');

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
        $this->extendedDesRounds = self::atLeastOne($rounds, 'extendedDesRounds');

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
        $this->argon2Memory = self::atLeastOne($kibibytes, 'argon2Memory');

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
        $this->argon2MemoryPasses = self::atLeastOne($kibibytePasses, 'argon2MemoryPasses');

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
        $this->argon2Threads = self::atLeastOne($threads, 'argon2Threads');

        return $this;
    }

    /**
     * @return positive-int
     *
     * @throws InvalidArgumentException
     */
    private static function atLeastOne(
        int $value,
        string $limit,
    ): int {
        if ($value >= 1) {
            return $value;
        }

        throw new InvalidArgumentException(sprintf(
            'The "%s" password hash limit must be at least 1.',
            $limit,
        ));
    }
}
