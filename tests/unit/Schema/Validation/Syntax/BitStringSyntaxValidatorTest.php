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

use FreeDSx\Ldap\Schema\Validation\Syntax\BitStringSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class BitStringSyntaxValidatorTest extends TestCase
{
    private BitStringSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new BitStringSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_quoted_binary_digits(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_malformed_bit_strings(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'uppercase suffix' => ["'0101'B"],
            'lowercase suffix' => ["'0101'b"],
            'single bit' => ["'1'B"],
            'empty bit string' => ["''B"],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'empty' => [''],
            'missing quotes' => ['0101'],
            'missing suffix' => ["'0101'"],
            'non binary digit' => ["'012'B"],
            'wrong suffix letter' => ["'0101'X"],
            'trailing newline' => ["'0101'B\n"],
        ];
    }
}
