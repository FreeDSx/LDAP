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

use FreeDSx\Ldap\Schema\Validation\Syntax\NumericStringSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class NumericStringSyntaxValidatorTest extends TestCase
{
    private NumericStringSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new NumericStringSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_digits_and_spaces(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_non_numeric_characters(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'digits' => ['12345'],
            'grouped with spaces' => ['15 079 672 281'],
            'single zero' => ['0'],
            'spaces only are permitted by the abnf' => ['   '],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'empty' => [''],
            'embedded letter' => ['12a45'],
            'hyphen' => ['12-34'],
            'decimal point' => ['12.34'],
            'trailing newline' => ["1234\n"],
        ];
    }
}
