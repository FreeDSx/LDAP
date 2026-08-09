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

use FreeDSx\Ldap\Schema\Validation\Syntax\DirectoryStringSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DirectoryStringSyntaxValidatorTest extends TestCase
{
    private DirectoryStringSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new DirectoryStringSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_non_empty_utf8_values(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_empty_and_malformed_values(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'ascii' => ['Jane Doe'],
            'accented letter' => ['café'],
            'multibyte' => ['名前'],
            'single space' => [' '],
            'emoji' => ['🔒'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'empty' => [''],
            'lone continuation byte' => ["\x80"],
            'truncated multibyte' => ["caf\xC3"],
            'overlong encoding' => ["\xC0\xAF"],
            'surrogate half' => ["\xED\xA0\x80"],
        ];
    }
}
