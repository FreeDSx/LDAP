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

namespace Tests\Unit\FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Schema\Text;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TextTest extends TestCase
{
    #[DataProvider('asciiProvider')]
    public function test_is_ascii(
        string $value,
        bool $expected,
    ): void {
        self::assertSame(
            $expected,
            Text::isAscii($value),
        );
    }

    #[DataProvider('printableAsciiProvider')]
    public function test_is_printable_ascii(
        string $value,
        bool $expected,
    ): void {
        self::assertSame(
            $expected,
            Text::isPrintableAscii($value),
        );
    }

    #[DataProvider('utf8Provider')]
    public function test_is_utf8(
        string $value,
        bool $expected,
    ): void {
        self::assertSame(
            $expected,
            Text::isUtf8($value),
        );
    }

    #[DataProvider('lengthProvider')]
    public function test_length_of(
        string $value,
        int $expected,
    ): void {
        self::assertSame(
            $expected,
            Text::lengthOf($value),
        );
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function asciiProvider(): array
    {
        return [
            'plain ascii' => ['user@example.com', true],
            'empty' => ['', true],
            'control characters' => ["tab\tnewline\n", true],
            'accented letter' => ['café', false],
            'emoji' => ['😀', false],
            'high byte' => ["\xFF", false],
        ];
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function printableAsciiProvider(): array
    {
        return [
            'plain ascii' => ['user@example.com', true],
            'empty' => ['', true],
            'space' => ['a b', true],
            'tab' => ["a\tb", false],
            'trailing newline' => ["cn\n", false],
            'delete' => ["a\x7Fb", false],
            'accented letter' => ['café', false],
        ];
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function utf8Provider(): array
    {
        return [
            'plain ascii' => ['plain', true],
            'empty' => ['', true],
            'multibyte' => ['café', true],
            'emoji' => ['😀', true],
            'high byte' => ["\xFF", false],
            'invalid two byte sequence' => ["\xC3\x28", false],
            'lone continuation byte' => ["\x80", false],
        ];
    }

    /**
     * @return array<string, array{string, int}>
     */
    public static function lengthProvider(): array
    {
        return [
            'ascii' => ['hello', 5],
            'empty' => ['', 0],
            'accented counts as one code point' => ['café', 4],
            'emoji counts as one code point' => ['😀', 1],
            'mixed' => ['a😀b', 3],
        ];
    }
}
