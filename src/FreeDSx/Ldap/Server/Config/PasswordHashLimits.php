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

/**
 * The most work a stored password hash may ask of the server, since verifying it costs what its own parameters say.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PasswordHashLimits
{
    public function __construct(
        private int $shaCryptRounds = 1_000_000,
        private int $bcryptCost = 14,
        private int $extendedDesRounds = 1_000_000,
        private int $argon2Memory = 262_144,
        private int $argon2MemoryPasses = 1_048_576,
        private int $argon2Threads = 4,
    ) {}

    /**
     * The most rounds a SHA-256 or SHA-512 crypt hash may name.
     */
    public function getShaCryptRounds(): int
    {
        return $this->shaCryptRounds;
    }

    public function setShaCryptRounds(int $rounds): self
    {
        $this->shaCryptRounds = $rounds;

        return $this;
    }

    /**
     * The highest bcrypt cost a hash may name.
     */
    public function getBcryptCost(): int
    {
        return $this->bcryptCost;
    }

    public function setBcryptCost(int $cost): self
    {
        $this->bcryptCost = $cost;

        return $this;
    }

    /**
     * The most rounds an extended DES crypt hash may name.
     */
    public function getExtendedDesRounds(): int
    {
        return $this->extendedDesRounds;
    }

    public function setExtendedDesRounds(int $rounds): self
    {
        $this->extendedDesRounds = $rounds;

        return $this;
    }

    /**
     * The most memory, in KiB, an argon2 hash may name.
     */
    public function getArgon2Memory(): int
    {
        return $this->argon2Memory;
    }

    public function setArgon2Memory(int $kibibytes): self
    {
        $this->argon2Memory = $kibibytes;

        return $this;
    }

    /**
     * The most memory times passes, in KiB, an argon2 hash may name.
     */
    public function getArgon2MemoryPasses(): int
    {
        return $this->argon2MemoryPasses;
    }

    public function setArgon2MemoryPasses(int $kibibytePasses): self
    {
        $this->argon2MemoryPasses = $kibibytePasses;

        return $this;
    }

    /**
     * The most threads an argon2 hash may name.
     */
    public function getArgon2Threads(): int
    {
        return $this->argon2Threads;
    }

    public function setArgon2Threads(int $threads): self
    {
        $this->argon2Threads = $threads;

        return $this;
    }
}
