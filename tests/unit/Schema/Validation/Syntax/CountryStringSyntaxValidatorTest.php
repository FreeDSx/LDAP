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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Validation\Syntax;

use FreeDSx\Ldap\Schema\Validation\Syntax\CountryStringSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CountryStringSyntaxValidatorTest extends TestCase
{
    private CountryStringSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new CountryStringSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_two_printable_characters(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_anything_other_than_two_printable_characters(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'country code' => ['US'],
            'another country code' => ['AU'],
            // RFC 4517 3.3.4 constrains the length, while ISO 3166 membership lives only in prose.
            'any two printable characters' => ['Z9'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'empty' => [''],
            'one character' => ['U'],
            'three characters' => ['USA'],
            'a country name' => ['UnitedStates'],
            'non printable character' => ["U\x00"],
            'trailing newline' => ["US\n"],
        ];
    }
}
