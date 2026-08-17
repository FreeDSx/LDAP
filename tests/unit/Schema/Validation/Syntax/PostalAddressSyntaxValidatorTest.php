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

use FreeDSx\Ldap\Schema\Validation\Syntax\PostalAddressSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PostalAddressSyntaxValidatorTest extends TestCase
{
    private PostalAddressSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new PostalAddressSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_a_conforming_address(string $value): void
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
            'the rfc example' => [
                '1234 Main St.$Anytown, CA 12345$USA',
            ],
            'a single line' => [
                'one line',
            ],
            'an escaped dollar' => [
                'costs \24 5',
            ],
            'an escaped backslash' => [
                'a\5Cb',
            ],
            'non ascii' => [
                "caf\u{00e9} street\$Paris",
            ],
            // The grammar makes a line at least one character, but common implementations store an empty one.
            'an empty line between separators' => [
                'a$$b',
            ],
            'a leading separator' => [
                '$leading',
            ],
            'a trailing separator' => [
                'trailing$',
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
            'a bare backslash' => [
                'a\b',
            ],
            'invalid utf-8' => [
                "bad \xC3\x28 line",
            ],
        ];
    }
}
