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

use FreeDSx\Ldap\Schema\Validation\Syntax\FacsimileTelephoneNumberSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class FacsimileTelephoneNumberSyntaxValidatorTest extends TestCase
{
    private FacsimileTelephoneNumberSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new FacsimileTelephoneNumberSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_a_number_with_optional_parameters(string $value): void
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
            'a number alone' => [
                '+1 555 555 1234',
            ],
            'one parameter' => [
                '+1 555 555 1234$fineResolution',
            ],
            'several parameters' => [
                '+1 555 555 1234$b4Width$a3Width$uncompressed',
            ],
            'every parameter' => [
                '+1 555$twoDimensional$fineResolution$unlimitedLength$b4Length$a3Width$b4Width$uncompressed',
            ],
            // RFC 5234 2.3 makes the quoted ABNF literals case-insensitive.
            'a parameter in another case' => [
                '+1 555$FineResolution',
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
            'an undefined parameter' => [
                '+1 555$bogusParameter',
            ],
            'a trailing separator' => [
                '+1 555$',
            ],
            'no number before the parameter' => [
                '$fineResolution',
            ],
            'a character outside printable string' => [
                '555#123',
            ],
        ];
    }
}
