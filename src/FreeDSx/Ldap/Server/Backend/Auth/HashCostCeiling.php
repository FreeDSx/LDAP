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

namespace FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Server\Config\PasswordHashLimits;

use function intdiv;
use function max;
use function preg_match;
use function str_starts_with;
use function strlen;
use function strpos;
use function substr;

/**
 * Decides whether a stored hash asks for no more work than the limits allow, and is in the format its scheme names.
 *
 * Note: The limits never fall below what the server's own scheme and cost produce, so its own hashes always verify.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class HashCostCeiling
{
    /**
     * A bcrypt hash: "$2a$", "$2b$", "$2x$" or "$2y$", then its two-digit cost.
     */
    private const BCRYPT = '/^\$2[abxy]\$(\d{2})\$/';

    /**
     * A SHA-256 ("$5$") or SHA-512 ("$6$") crypt hash.
     */
    private const SHA_CRYPT = '/^\$[56]\$/';

    /**
     * The round count of a SHA crypt hash, in the only spelling of it this reads.
     */
    private const SHA_CRYPT_ROUNDS = '/^\$[56]\$rounds=(\d+)\$/';

    /**
     * An extended DES crypt hash: an underscore, then four characters encoding its round count.
     */
    private const EXTENDED_DES = '/^_([.\/0-9A-Za-z]{4})/';

    /**
     * An argon2i or argon2id hash, with its memory in KiB, its passes and its threads.
     */
    private const ARGON2 = '/^\$argon2(?:i|id)\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$/';

    /**
     * The rounds a SHA crypt hash runs when it names none.
     */
    private const SHA_CRYPT_DEFAULT_ROUNDS = 5000;

    /**
     * The characters crypt() encodes an extended DES round count in, least significant first.
     */
    private const CRYPT_ALPHABET = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    public function __construct(
        private PasswordHashLimits $limits = new PasswordHashLimits(),
        private PasswordHashScheme $scheme = PasswordHashScheme::Bcrypt,
        private ?int $hashCost = null,
    ) {}

    /**
     * Whether a value stored under the scheme (without its prefix) is one the server may spend a verify on.
     */
    public function admits(
        string $scheme,
        string $encoded,
    ): bool {
        return match ('{' . $scheme . '}') {
            PasswordHashScheme::Bcrypt->value => $this->admitsBcrypt($encoded),
            PasswordHashScheme::Argon2->value => $this->admitsArgon2($encoded),
            '{CRYPT}' => $this->admitsCrypt($encoded),
            default => true,
        };
    }

    private function admitsBcrypt(string $encoded): bool
    {
        if (preg_match(self::BCRYPT, $encoded, $matches) !== 1) {
            return false;
        }

        return (int) $matches[1] <= $this->bcryptCost();
    }

    private function admitsArgon2(string $encoded): bool
    {
        if (preg_match(self::ARGON2, $encoded, $matches) !== 1) {
            return false;
        }
        $memory = max(
            (int) $matches[1],
            1,
        );

        return $memory <= $this->argon2Memory()
            && (int) $matches[2] <= intdiv($this->argon2MemoryPasses(), $memory)
            && (int) $matches[3] <= $this->argon2Threads();
    }

    private function admitsCrypt(string $encoded): bool
    {
        if (str_starts_with($encoded, '$2')) {
            return $this->admitsBcrypt($encoded);
        }
        if (preg_match(self::SHA_CRYPT, $encoded) === 1) {
            return $this->admitsShaCrypt($encoded);
        }
        if (str_starts_with($encoded, '_')) {
            return preg_match(self::EXTENDED_DES, $encoded, $matches) === 1
                && self::extendedDesRounds($matches[1]) <= $this->limits->getExtendedDesRounds();
        }

        // MD5 and traditional DES cost the same every time; no other "$" format is worth a verify.
        return str_starts_with($encoded, '$1$') || !str_starts_with($encoded, '$');
    }

    /**
     * A round count spelled other than in plain digits is refused, since crypt() reads spellings this does not.
     */
    private function admitsShaCrypt(string $encoded): bool
    {
        if (!str_starts_with(substr($encoded, 3), 'rounds=')) {
            return self::SHA_CRYPT_DEFAULT_ROUNDS <= $this->limits->getShaCryptRounds();
        }

        return preg_match(self::SHA_CRYPT_ROUNDS, $encoded, $matches) === 1
            && (int) $matches[1] <= $this->limits->getShaCryptRounds();
    }

    private function bcryptCost(): int
    {
        if ($this->scheme !== PasswordHashScheme::Bcrypt) {
            return $this->limits->getBcryptCost();
        }

        return max(
            $this->limits->getBcryptCost(),
            $this->hashCost ?? PASSWORD_BCRYPT_DEFAULT_COST,
        );
    }

    private function argon2Memory(): int
    {
        if ($this->scheme !== PasswordHashScheme::Argon2) {
            return $this->limits->getArgon2Memory();
        }

        return max(
            $this->limits->getArgon2Memory(),
            PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
        );
    }

    private function argon2MemoryPasses(): int
    {
        if ($this->scheme !== PasswordHashScheme::Argon2) {
            return $this->limits->getArgon2MemoryPasses();
        }

        return max(
            $this->limits->getArgon2MemoryPasses(),
            PASSWORD_ARGON2_DEFAULT_MEMORY_COST * PASSWORD_ARGON2_DEFAULT_TIME_COST,
        );
    }

    private function argon2Threads(): int
    {
        if ($this->scheme !== PasswordHashScheme::Argon2) {
            return $this->limits->getArgon2Threads();
        }

        return max(
            $this->limits->getArgon2Threads(),
            PASSWORD_ARGON2_DEFAULT_THREADS,
        );
    }

    private static function extendedDesRounds(string $count): int
    {
        $rounds = 0;

        for ($i = 0; $i < strlen($count); $i++) {
            $rounds |= (int) strpos(self::CRYPT_ALPHABET, $count[$i]) << (6 * $i);
        }

        return $rounds;
    }
}
