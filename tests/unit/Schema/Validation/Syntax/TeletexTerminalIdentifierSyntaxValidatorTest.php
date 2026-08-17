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

use FreeDSx\Ldap\Schema\Validation\Syntax\TeletexTerminalIdentifierSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TeletexTerminalIdentifierSyntaxValidatorTest extends TestCase
{
    private TeletexTerminalIdentifierSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new TeletexTerminalIdentifierSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_a_terminal_with_optional_parameters(string $value): void
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
            'a terminal alone' => [
                'terminal-1',
            ],
            'one parameter' => [
                'terminal-1$graphic:on',
            ],
            'every key' => [
                'term$graphic:a$control:b$misc:c$page:d$private:e',
            ],
            'an empty parameter value' => [
                'term$page:',
            ],
            // RFC 5234 2.3 makes the quoted ABNF literals case-insensitive.
            'a key in another case' => [
                'term$Graphic:on',
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
            'an undefined key' => [
                'term$bogus:x',
            ],
            'a parameter with no key separator' => [
                'term$graphic',
            ],
            'no terminal before the parameter' => [
                '$graphic:on',
            ],
            'a terminal outside printable string' => [
                "term\x01\$graphic:on",
            ],
        ];
    }
}
