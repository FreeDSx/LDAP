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

use FreeDSx\Ldap\Schema\Validation\Syntax\PrintableStringSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PrintableStringSyntaxValidatorTest extends TestCase
{
    private PrintableStringSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new PrintableStringSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_printable_characters(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_non_printable_characters(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'words' => ['Hello World'],
            'punctuation subset' => ['Example Co., Ltd.'],
            'apostrophe and digits' => ["abc'123"],
            'operators' => ['a+b=c'],
            'parentheses and question mark' => ['(who?)'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'empty' => [''],
            'hash' => ['hash#'],
            'at sign' => ['user@host'],
            'asterisk' => ['a*b'],
            'non ascii letter' => ['unicodé'],
            'trailing newline' => ["abc\n"],
        ];
    }
}
