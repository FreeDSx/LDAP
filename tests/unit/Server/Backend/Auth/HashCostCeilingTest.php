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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Server\Backend\Auth\HashCostCeiling;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\Config\PasswordHashLimits;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function str_repeat;

final class HashCostCeilingTest extends TestCase
{
    private const BCRYPT_TAIL = 'abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234';

    private HashCostCeiling $subject;

    protected function setUp(): void
    {
        $this->subject = new HashCostCeiling();
    }

    #[DataProvider('defaultLimitsProvider')]
    public function test_the_default_limits_admit_only_hashes_within_them(
        string $scheme,
        string $encoded,
        bool $admitted,
    ): void {
        self::assertSame(
            $admitted,
            $this->subject->admits(
                $scheme,
                $encoded,
            ),
        );
    }

    /**
     * @return Generator<string, array{string, string, bool}>
     */
    public static function defaultLimitsProvider(): Generator
    {
        yield 'bcrypt at the cost limit' => [
            'BCRYPT',
            '$2y$14$' . self::BCRYPT_TAIL,
            true,
        ];
        yield 'bcrypt over the cost limit' => [
            'BCRYPT',
            '$2y$15$' . self::BCRYPT_TAIL,
            false,
        ];
        yield 'bcrypt under the crypt tag at the cost limit' => [
            'CRYPT',
            '$2a$14$' . self::BCRYPT_TAIL,
            true,
        ];
        yield 'bcrypt under the crypt tag over the cost limit' => [
            'CRYPT',
            '$2b$15$' . self::BCRYPT_TAIL,
            false,
        ];
        yield 'bcrypt with the 2x prefix under the crypt tag at the cost limit' => [
            'CRYPT',
            '$2x$14$' . self::BCRYPT_TAIL,
            true,
        ];
        yield 'bcrypt with the 2x prefix under the crypt tag over the cost limit' => [
            'CRYPT',
            '$2x$15$' . self::BCRYPT_TAIL,
            false,
        ];
        yield 'bcrypt with the 2x prefix under the bcrypt tag over the cost limit' => [
            'BCRYPT',
            '$2x$15$' . self::BCRYPT_TAIL,
            false,
        ];
        yield 'a bcrypt prefix this does not read under the crypt tag' => [
            'CRYPT',
            '$2c$10$' . self::BCRYPT_TAIL,
            false,
        ];
        yield 'sha-crypt rounds spelled with a plus sign' => [
            'CRYPT',
            '$6$rounds=+3000000$saltsalt$hash',
            false,
        ];
        yield 'sha-crypt rounds spelled with a leading space' => [
            'CRYPT',
            '$6$rounds= 3000000$saltsalt$hash',
            false,
        ];
        yield 'sha-crypt rounds spelled with a leading tab' => [
            'CRYPT',
            "\$6\$rounds=\t3000000\$saltsalt\$hash",
            false,
        ];
        yield 'sha-crypt rounds that wrap around from a negative count' => [
            'CRYPT',
            '$6$rounds=-18446744073707551616$saltsalt$hash',
            false,
        ];
        yield 'a malformed extended DES hash' => [
            'CRYPT',
            '_!!!!saltabcdefghijk',
            false,
        ];
        yield 'a crypt format PHP does not verify' => [
            'CRYPT',
            '$y$j9T$saltsalt$hash',
            false,
        ];
        yield 'sha-512 crypt under the bcrypt tag' => [
            'BCRYPT',
            '$6$rounds=5000$saltsalt$hash',
            false,
        ];
        yield 'argon2 under the bcrypt tag' => [
            'BCRYPT',
            '$argon2id$v=19$m=65536,t=4,p=1$c2FsdA$aGFzaA',
            false,
        ];
        yield 'bcrypt under the argon2 tag' => [
            'ARGON2',
            '$2y$10$' . self::BCRYPT_TAIL,
            false,
        ];
        yield 'sha-512 crypt at the round limit' => [
            'CRYPT',
            '$6$rounds=1000000$saltsalt$hash',
            true,
        ];
        yield 'sha-512 crypt over the round limit' => [
            'CRYPT',
            '$6$rounds=1000001$saltsalt$hash',
            false,
        ];
        yield 'sha-256 crypt over the round limit' => [
            'CRYPT',
            '$5$rounds=1000001$saltsalt$hash',
            false,
        ];
        yield 'sha-crypt naming no rounds' => [
            'CRYPT',
            '$6$saltsalt$hash',
            true,
        ];
        yield 'sha-crypt with a round count past the integer range' => [
            'CRYPT',
            '$6$rounds=99999999999999999999$saltsalt$hash',
            false,
        ];
        yield 'extended DES at the round limit' => [
            'CRYPT',
            '_.7o1saltabcdefghijk',
            true,
        ];
        yield 'extended DES over the round limit' => [
            'CRYPT',
            '_/7o1saltabcdefghijk',
            false,
        ];
        yield 'extended DES at its format maximum' => [
            'CRYPT',
            '_zzzzsaltabcdefghijk',
            false,
        ];
        yield 'md5 crypt' => [
            'CRYPT',
            '$1$saltsalt$hash',
            true,
        ];
        yield 'traditional DES crypt' => [
            'CRYPT',
            'abhashhashhas',
            true,
        ];
        yield 'argon2id at the PHP defaults' => [
            'ARGON2',
            '$argon2id$v=19$m=65536,t=4,p=1$c2FsdA$aGFzaA',
            true,
        ];
        yield 'argon2i at the memory and pass limits' => [
            'ARGON2',
            '$argon2i$v=19$m=262144,t=4,p=4$c2FsdA$aGFzaA',
            true,
        ];
        yield 'argon2 over the memory limit' => [
            'ARGON2',
            '$argon2id$v=19$m=262145,t=1,p=1$c2FsdA$aGFzaA',
            false,
        ];
        yield 'argon2 over the memory times passes limit' => [
            'ARGON2',
            '$argon2id$v=19$m=262144,t=5,p=1$c2FsdA$aGFzaA',
            false,
        ];
        yield 'argon2 over the thread limit' => [
            'ARGON2',
            '$argon2id$v=19$m=65536,t=4,p=5$c2FsdA$aGFzaA',
            false,
        ];
        yield 'argon2 with a memory past the integer range' => [
            'ARGON2',
            '$argon2id$v=19$m=99999999999999999999,t=1,p=1$c2FsdA$aGFzaA',
            false,
        ];
        yield 'a scheme with no work factor' => [
            'SSHA',
            'c2FsdGVkaGFzaA==',
            true,
        ];
    }

    public function test_lowered_limits_refuse_what_the_defaults_admit(): void
    {
        $subject = new HashCostCeiling(new PasswordHashLimits(shaCryptRounds: 10_000));

        self::assertFalse($subject->admits(
            'CRYPT',
            '$6$rounds=10001$saltsalt$hash',
        ));
    }

    public function test_the_bcrypt_limit_never_falls_below_the_cost_the_server_hashes_with(): void
    {
        $subject = new HashCostCeiling(
            new PasswordHashLimits(bcryptCost: 10),
            PasswordHashScheme::Bcrypt,
            12,
        );

        self::assertTrue($subject->admits(
            'BCRYPT',
            '$2y$12$' . self::BCRYPT_TAIL,
        ));
        self::assertFalse($subject->admits(
            'BCRYPT',
            '$2y$13$' . self::BCRYPT_TAIL,
        ));
    }

    public function test_the_argon2_limits_never_fall_below_what_the_server_hashes_with(): void
    {
        $subject = new HashCostCeiling(
            new PasswordHashLimits(
                argon2Memory: 1024,
                argon2MemoryPasses: 1024,
                argon2Threads: 1,
            ),
            PasswordHashScheme::Argon2,
        );

        self::assertTrue($subject->admits(
            'ARGON2',
            '$argon2id$v=19$m=65536,t=4,p=1$c2FsdA$aGFzaA',
        ));
    }

    public function test_the_server_cost_raises_no_limit_for_a_scheme_it_does_not_hash_with(): void
    {
        $subject = new HashCostCeiling(
            new PasswordHashLimits(bcryptCost: 10),
            PasswordHashScheme::Argon2,
            12,
        );

        self::assertFalse($subject->admits(
            'BCRYPT',
            '$2y$11$' . str_repeat('a', 53),
        ));
    }

    public function test_a_password_at_the_default_length_limit_is_admitted(): void
    {
        self::assertTrue($this->subject->admitsPassword(str_repeat('a', 512)));
    }

    public function test_a_password_over_the_default_length_limit_is_refused(): void
    {
        self::assertFalse($this->subject->admitsPassword(str_repeat('a', 513)));
    }

    public function test_a_password_over_a_lowered_length_limit_is_refused(): void
    {
        $subject = new HashCostCeiling(new PasswordHashLimits(maxPasswordLength: 64));

        self::assertFalse($subject->admitsPassword(str_repeat('a', 65)));
    }
}
