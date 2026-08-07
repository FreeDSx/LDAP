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

use FreeDSx\Ldap\Exception\RuntimeException;
use SensitiveParameter;

/**
 * Hashes, generates, and verifies userPassword values; writes the configured scheme and reads legacy {SHA}/{MD5}/{SMD5}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PasswordHashService
{
    /**
     * Read-only legacy prefixes recognized in addition to the writable {@see PasswordHashScheme} set.
     *
     * @var list<string>
     */
    private const LEGACY_READ_PREFIXES = [
        '{SHA}',
        '{MD5}',
        '{SMD5}',
    ];

    /**
     * @param int|null $hashCost bcrypt cost forwarded to password_hash(); null uses the PHP default (10). Does not apply to argon2.
     */
    public function __construct(
        private PasswordHashScheme $scheme = PasswordHashScheme::Bcrypt,
        private ?int $hashCost = null,
    ) {}

    /**
     * Whether a value begins with a recognized hash scheme, and so is not cleartext we can inspect.
     */
    public function isHashed(string $value): bool
    {
        foreach ($this->recognizedPrefixes() as $prefix) {
            if (str_starts_with($value, $prefix)) {
                return true;
            }
        }

        return false;
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
        foreach ($this->recognizedPrefixes() as $prefix) {
            if (str_starts_with($stored, $prefix)) {
                return $this->verifyScheme(
                    $prefix,
                    $plain,
                    substr($stored, strlen($prefix)),
                );
            }
        }

        return hash_equals(
            $stored,
            $plain,
        );
    }

    /**
     * Prefixes recognized for verification.
     *
     * @return list<string>
     */
    private function recognizedPrefixes(): array
    {
        return [
            ...array_map(
                static fn(PasswordHashScheme $scheme): string => $scheme->value,
                PasswordHashScheme::cases(),
            ),
            ...self::LEGACY_READ_PREFIXES,
        ];
    }

    private function verifyScheme(
        string $prefix,
        #[SensitiveParameter]
        string $plain,
        string $encoded,
    ): bool {
        return match ($prefix) {
            PasswordHashScheme::Ssha->value => $this->verifySsha($plain, $encoded),
            PasswordHashScheme::Bcrypt->value, PasswordHashScheme::Argon2->value => password_verify($plain, $encoded),
            '{SHA}' => $this->verifySha($plain, $encoded),
            '{MD5}' => $this->verifyMd5($plain, $encoded),
            '{SMD5}' => $this->verifySmd5($plain, $encoded),
            default => throw new RuntimeException(sprintf(
                'No verification is implemented for the recognized hash scheme "%s".',
                $prefix,
            )),
        };
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
