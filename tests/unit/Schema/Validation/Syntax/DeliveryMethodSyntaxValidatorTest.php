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

use FreeDSx\Ldap\Schema\Validation\Syntax\DeliveryMethodSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DeliveryMethodSyntaxValidatorTest extends TestCase
{
    private DeliveryMethodSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new DeliveryMethodSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_the_defined_keywords(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_anything_outside_the_grammar(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'a single method' => [
                'telephone',
            ],
            'spaces around the separator' => [
                'telephone $ physical',
            ],
            'no spaces around the separator' => [
                'any$mhs',
            ],
            'every keyword' => [
                'any $ mhs $ physical $ telex $ teletex $ g3fax $ g4fax $ ia5 $ videotex $ telephone',
            ],
            // RFC 5234 2.3 makes the quoted ABNF literals case-insensitive.
            'a keyword in another case' => [
                'Telephone',
            ],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'empty' => [
                '',
            ],
            'an undefined keyword' => [
                'carrier-pigeon',
            ],
            'a trailing separator' => [
                'telephone $',
            ],
            'a leading separator' => [
                '$ telephone',
            ],
            'a keyword with surrounding text' => [
                'use telephone',
            ],
        ];
    }
}
