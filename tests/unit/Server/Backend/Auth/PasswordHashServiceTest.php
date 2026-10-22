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

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PasswordHashServiceTest extends TestCase
{
    private PasswordHashService $subject;

    protected function setUp(): void
    {
        $this->subject = new PasswordHashService(hashCost: 4);
    }

    public function test_default_scheme_is_bcrypt(): void
    {
        self::assertStringStartsWith(
            '{BCRYPT}',
            $this->subject->hash('secret'),
        );
    }

    /**
     * @return array<string, array{0: PasswordHashScheme, 1: non-empty-string}>
     */
    public static function schemeProvider(): array
    {
        return [
            'ssha' => [PasswordHashScheme::Ssha, '{SSHA}'],
            'bcrypt' => [PasswordHashScheme::Bcrypt, '{BCRYPT}'],
            'argon2' => [PasswordHashScheme::Argon2, '{ARGON2}'],
        ];
    }

    /**
     * @param non-empty-string $expectedPrefix
     */
    #[DataProvider('schemeProvider')]
    public function test_each_scheme_produces_its_prefix(
        PasswordHashScheme $scheme,
        string $expectedPrefix,
    ): void {
        $hashed = (new PasswordHashService($scheme, hashCost: 4))->hash('secret');

        self::assertStringStartsWith(
            $expectedPrefix,
            $hashed,
        );
    }

    #[DataProvider('schemeProvider')]
    public function test_each_scheme_round_trips(
        PasswordHashScheme $scheme,
    ): void {
        $hashed = (new PasswordHashService($scheme, hashCost: 4))->hash('mypassword');

        self::assertTrue($this->subject->verify(
            'mypassword',
            $hashed,
        ));
    }

    #[DataProvider('schemeProvider')]
    public function test_wrong_password_does_not_verify_a_freshly_hashed_value(
        PasswordHashScheme $scheme,
    ): void {
        $hashed = (new PasswordHashService($scheme, hashCost: 4))->hash('mypassword');

        self::assertFalse($this->subject->verify(
            'wrong',
            $hashed,
        ));
    }

    #[DataProvider('schemeProvider')]
    public function test_two_hashes_of_same_input_differ_due_to_random_salt(
        PasswordHashScheme $scheme,
    ): void {
        $hasher = new PasswordHashService($scheme, hashCost: 4);

        self::assertNotSame(
            $hasher->hash('password'),
            $hasher->hash('password'),
        );
    }

    public function test_generate_returns_16_character_string(): void
    {
        self::assertSame(
            16,
            strlen($this->subject->generate()),
        );
    }

    public function test_generate_produces_different_values_on_each_call(): void
    {
        self::assertNotSame(
            $this->subject->generate(),
            $this->subject->generate(),
        );
    }

    public function test_plaintext_verifies_when_equal(): void
    {
        self::assertTrue($this->subject->verify(
            'secret',
            'secret',
        ));
    }

    public function test_plaintext_does_not_verify_when_different(): void
    {
        self::assertFalse($this->subject->verify(
            'secret',
            'other',
        ));
    }

    public function test_an_empty_stored_value_does_not_verify_against_an_empty_password(): void
    {
        self::assertFalse($this->subject->verify(
            '',
            '',
        ));
    }

    public function test_an_empty_stored_value_does_not_verify(): void
    {
        self::assertFalse($this->subject->verify(
            'secret',
            '',
        ));
    }

    public function test_an_empty_password_does_not_verify(): void
    {
        self::assertFalse($this->subject->verify(
            '',
            'secret',
        ));
    }

    public function test_an_empty_password_does_not_verify_against_a_hash_of_one(): void
    {
        self::assertFalse($this->subject->verify(
            '',
            $this->subject->hash(''),
        ));
    }

    public function test_a_whitespace_only_password_still_verifies(): void
    {
        self::assertTrue($this->subject->verify(
            ' ',
            ' ',
        ));
    }

    public function test_sha_format_verifies(): void
    {
        $hashed = '{SHA}' . base64_encode(sha1('mypassword', true));

        self::assertTrue($this->subject->verify(
            'mypassword',
            $hashed,
        ));
    }

    public function test_ssha_format_verifies(): void
    {
        $salt = random_bytes(8);
        $hashed = '{SSHA}' . base64_encode(sha1('mypassword' . $salt, true) . $salt);

        self::assertTrue($this->subject->verify(
            'mypassword',
            $hashed,
        ));
    }

    public function test_md5_format_verifies(): void
    {
        $hashed = '{MD5}' . base64_encode(md5('mypassword', true));

        self::assertTrue($this->subject->verify(
            'mypassword',
            $hashed,
        ));
    }

    public function test_smd5_format_verifies(): void
    {
        $salt = random_bytes(8);
        $hashed = '{SMD5}' . base64_encode(md5('mypassword' . $salt, true) . $salt);

        self::assertTrue($this->subject->verify(
            'mypassword',
            $hashed,
        ));
    }

    public function test_bcrypt_format_verifies(): void
    {
        $hashed = '{BCRYPT}' . password_hash('mypassword', PASSWORD_BCRYPT, ['cost' => 4]);

        self::assertTrue($this->subject->verify(
            'mypassword',
            $hashed,
        ));
    }

    public function test_argon2_format_verifies(): void
    {
        $hashed = '{ARGON2}' . password_hash('mypassword', PASSWORD_ARGON2ID);

        self::assertTrue($this->subject->verify(
            'mypassword',
            $hashed,
        ));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function hashedPrefixProvider(): array
    {
        return [
            '{SHA}'    => ['{SHA}' . base64_encode(sha1('mypassword', true))],
            '{MD5}'    => ['{MD5}' . base64_encode(md5('mypassword', true))],
            '{BCRYPT}' => ['{BCRYPT}' . password_hash('mypassword', PASSWORD_BCRYPT, ['cost' => 4])],
            '{ARGON2}' => ['{ARGON2}' . password_hash('mypassword', PASSWORD_ARGON2ID)],
        ];
    }

    #[DataProvider('hashedPrefixProvider')]
    public function test_wrong_password_does_not_verify_against_a_known_hash(string $hashed): void
    {
        self::assertFalse($this->subject->verify(
            'wrong',
            $hashed,
        ));
    }

    public function test_is_hashed_recognizes_scheme_prefixes(): void
    {
        self::assertTrue($this->subject->isHashed('{SSHA}whatever'));
        self::assertTrue($this->subject->isHashed('{BCRYPT}whatever'));
        self::assertTrue($this->subject->isHashed('{SHA}whatever'));
    }

    public function test_is_hashed_treats_plaintext_as_not_hashed(): void
    {
        self::assertFalse($this->subject->isHashed('plaintext'));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function cryptSaltProvider(): array
    {
        return [
            'sha-512' => ['$6$rounds=5000$saltsaltsalt$'],
            'sha-256' => ['$5$saltsaltsalt$'],
            'md5' => ['$1$saltsalt$'],
            'bcrypt' => ['$2y$04$abcdefghijklmnopqrstuu'],
            'des' => ['ab'],
        ];
    }

    #[DataProvider('cryptSaltProvider')]
    public function test_crypt_format_verifies_with_the_algorithm_its_hash_names(string $salt): void
    {
        $hashed = '{CRYPT}' . crypt(
            'mypassword',
            $salt,
        );

        self::assertTrue($this->subject->verify(
            'mypassword',
            $hashed,
        ));
        self::assertFalse($this->subject->verify(
            'wrong',
            $hashed,
        ));
    }

    public function test_a_crypt_value_without_a_usable_hash_does_not_verify(): void
    {
        self::assertFalse($this->subject->verify(
            'mypassword',
            '{CRYPT}',
        ));
        self::assertFalse($this->subject->verify(
            '*0',
            '{CRYPT}*0',
        ));
    }

    public function test_a_scheme_name_is_recognized_in_any_case(): void
    {
        self::assertTrue($this->subject->verify(
            'mypassword',
            '{crypt}' . crypt(
                'mypassword',
                '$6$saltsaltsalt$',
            ),
        ));
        self::assertTrue($this->subject->verify(
            'mypassword',
            '{sha}' . base64_encode(sha1(
                'mypassword',
                true,
            )),
        ));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function unsupportedSchemeProvider(): array
    {
        return [
            'salted sha-256' => [
                '{SSHA256}' . base64_encode(hash(
                    'sha256',
                    'mypassword',
                    true,
                )),
            ],
            'pbkdf2 with a hyphen' => ['{PBKDF2-SHA512}10000$c2FsdA$aGFzaA'],
            'pbkdf2 with an underscore' => ['{PBKDF2_SHA256}AAAIAA'],
            'dotted scheme' => ['{SHA256.HEX}89e01536ac207279409d4de1e5253e01f4a1769e696db0d6062ca9b8f56767c8'],
            'leading digit' => ['{1st}word'],
            'rfc 2307 alternative scheme' => ['{x-custom}mypassword'],
        ];
    }

    #[DataProvider('unsupportedSchemeProvider')]
    public function test_an_unsupported_scheme_never_verifies_not_even_against_the_stored_value(string $stored): void
    {
        self::assertTrue($this->subject->isHashed($stored));
        self::assertFalse($this->subject->verify(
            'mypassword',
            $stored,
        ));
        self::assertFalse($this->subject->verify(
            $stored,
            $stored,
        ));
    }

    #[DataProvider('unsupportedSchemeProvider')]
    public function test_an_unsupported_scheme_is_refused_as_unverifiable(string $stored): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->subject->assertVerifiable($stored);
    }

    public function test_an_unverifiable_value_is_refused_by_its_scheme_name(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "{PBKDF2-SHA512}" password scheme is not supported.');

        $this->subject->assertVerifiable('{pbkdf2-sha512}10000$c2FsdA$aGFzaA');
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function verifiableValueProvider(): array
    {
        return [
            'cleartext' => ['mypassword'],
            'brace-led cleartext' => ['{my pass}word'],
            'ssha' => ['{SSHA}c2FsdGVkaGFzaA=='],
            'bcrypt in lower case' => ['{bcrypt}$2y$04$abcdefghijklmnopqrstuu'],
            'argon2' => ['{ARGON2}$argon2id$v=19$m=65536,t=4,p=1$c2FsdA$aGFzaA'],
            'sha' => ['{SHA}aGFzaA=='],
            'md5' => ['{MD5}aGFzaA=='],
            'smd5' => ['{SMD5}aGFzaA=='],
            'crypt' => ['{CRYPT}$6$saltsaltsalt$hash'],
        ];
    }

    #[DataProvider('verifiableValueProvider')]
    public function test_cleartext_and_every_supported_scheme_are_verifiable(string $stored): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertVerifiable($stored);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function braceLedCleartextProvider(): array
    {
        return [
            'space in the braces' => ['{my pass}word'],
            'empty braces' => ['{}word'],
            'no closing brace' => ['{word'],
        ];
    }

    #[DataProvider('braceLedCleartextProvider')]
    public function test_a_value_whose_braces_are_not_a_scheme_prefix_is_cleartext(string $stored): void
    {
        self::assertFalse($this->subject->isHashed($stored));
        self::assertTrue($this->subject->verify(
            $stored,
            $stored,
        ));
    }
}
