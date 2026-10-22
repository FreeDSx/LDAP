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

use Closure;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * Hashes, generates, and verifies userPassword values; writes the configured scheme and reads {SHA}/{MD5}/{SMD5}/{CRYPT}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PasswordHashService
{
    /**
     * The {SCHEME} prefix, its name made of RFC 3112 scheme characters in either case.
     */
    private const SCHEME_PREFIX = '/^\{([A-Za-z0-9.\/_-]+)\}/';

    /**
     * @param int|null $hashCost bcrypt cost forwarded to password_hash(); null uses the PHP default. Does not apply to argon2.
     */
    public function __construct(
        private PasswordHashScheme $scheme = PasswordHashScheme::Bcrypt,
        private ?int $hashCost = null,
    ) {}

    /**
     * Whether a value carries a {SCHEME} prefix, recognized or not, which makes it something other than cleartext.
     */
    public function isHashed(string $value): bool
    {
        return $this->schemeOf($value) !== null;
    }

    /**
     * Hash a plaintext password using the configured scheme.
     */
    public function hash(
        #[SensitiveParameter]
        string $plain,
    ): string {
        return match ($this->scheme) {
            PasswordHashScheme::Ssha => $this->hashSsha($plain),
            PasswordHashScheme::Bcrypt => $this->hashWithPhpAlgo(
                $plain,
                PASSWORD_BCRYPT,
                PasswordHashScheme::Bcrypt,
            ),
            PasswordHashScheme::Argon2 => $this->hashWithPhpAlgo(
                $plain,
                PASSWORD_ARGON2ID,
                PasswordHashScheme::Argon2,
            ),
        };
    }

    /**
     * Generate a cryptographically random 16-character password.
     */
    public function generate(): string
    {
        return bin2hex(random_bytes(8));
    }

    public function verify(
        #[SensitiveParameter]
        string $plain,
        string $stored,
    ): bool {
        // An empty value on either side is the absence of a credential, never a match for one.
        if ($plain === '' || $stored === '') {
            return false;
        }

        $scheme = $this->schemeOf($stored);

        if ($scheme === null) {
            return hash_equals(
                $stored,
                $plain,
            );
        }
        $verifier = $this->verifierFor($scheme);

        return $verifier !== null && $verifier(
            $plain,
            substr(
                $stored,
                strlen($scheme) + 2,
            ),
        );
    }

    /**
     * Refuses a stored value under a scheme with no verification.
     *
     * @throws InvalidArgumentException naming the unsupported scheme
     */
    public function assertVerifiable(string $stored): void
    {
        $scheme = $this->schemeOf($stored);

        if ($scheme === null || $this->verifierFor($scheme) !== null) {
            return;
        }

        throw new InvalidArgumentException(sprintf(
            'The "{%s}" password scheme is not supported.',
            $scheme,
        ));
    }

    /**
     * Stands in for a skipped comparison, hashing costing the same as verifying under every supported scheme.
     */
    public function verifyDummy(
        #[SensitiveParameter]
        string $plain,
    ): void {
        $this->hash($plain);
    }

    /**
     * The upper-cased scheme a value's {SCHEME} prefix names, or null for a value without one.
     */
    private function schemeOf(string $value): ?string
    {
        $matched = preg_match(
            self::SCHEME_PREFIX,
            $value,
            $matches,
        );

        return $matched === 1
            ? strtoupper($matches[1])
            : null;
    }

    /**
     * The comparison for a scheme, or null for a scheme this service cannot verify.
     *
     * @return (Closure(string, string): bool)|null
     */
    private function verifierFor(string $scheme): ?Closure
    {
        return match ('{' . $scheme . '}') {
            PasswordHashScheme::Ssha->value => $this->verifySsha(...),
            PasswordHashScheme::Bcrypt->value, PasswordHashScheme::Argon2->value => password_verify(...),
            '{SHA}' => $this->verifySha(...),
            '{MD5}' => $this->verifyMd5(...),
            '{SMD5}' => $this->verifySmd5(...),
            '{CRYPT}' => $this->verifyCrypt(...),
            default => null,
        };
    }

    private function verifyCrypt(
        #[SensitiveParameter]
        string $plain,
        string $encoded,
    ): bool {
        return hash_equals(
            $encoded,
            crypt(
                $plain,
                $encoded,
            ),
        );
    }

    private function hashSsha(
        #[SensitiveParameter]
        string $plain,
    ): string {
        $salt = random_bytes(8);

        return PasswordHashScheme::Ssha->value
            . base64_encode(sha1($plain . $salt, true) . $salt);
    }

    private function hashWithPhpAlgo(
        #[SensitiveParameter]
        string $plain,
        string $algo,
        PasswordHashScheme $scheme,
    ): string {
        $hash = password_hash(
            $plain,
            $algo,
            $this->hashCost !== null
                ? ['cost' => $this->hashCost]
                : [],
        );

        return $scheme->value . $hash;
    }

    private function verifySha(
        #[SensitiveParameter]
        string $plain,
        string $encoded,
    ): bool {
        return hash_equals(
            $encoded,
            base64_encode(sha1($plain, true)),
        );
    }

    private function verifySsha(
        #[SensitiveParameter]
        string $plain,
        string $encoded,
    ): bool {
        $decoded = base64_decode($encoded);
        $salt = substr($decoded, 20);

        return hash_equals(
            substr($decoded, 0, 20),
            sha1($plain . $salt, true),
        );
    }

    private function verifyMd5(
        #[SensitiveParameter]
        string $plain,
        string $encoded,
    ): bool {
        return hash_equals(
            $encoded,
            base64_encode(md5($plain, true)),
        );
    }

    private function verifySmd5(
        #[SensitiveParameter]
        string $plain,
        string $encoded,
    ): bool {
        $decoded = base64_decode($encoded);
        $salt = substr($decoded, 16);

        return hash_equals(
            substr($decoded, 0, 16),
            md5($plain . $salt, true),
        );
    }
}
