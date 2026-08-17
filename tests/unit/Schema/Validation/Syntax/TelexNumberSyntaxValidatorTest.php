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

use FreeDSx\Ldap\Schema\Validation\Syntax\TelexNumberSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TelexNumberSyntaxValidatorTest extends TestCase
{
    private TelexNumberSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new TelexNumberSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_all_three_components(string $value): void
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
            'number, country and answerback' => [
                '12345$US$ACME',
            ],
            'printable punctuation' => [
                '(0)12-345$G.B.$ACME CO',
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
            'only two components' => [
                '12345$US',
            ],
            'four components' => [
                '1$2$3$4',
            ],
            'an empty component' => [
                '12345$$ACME',
            ],
            'a component outside printable string' => [
                "12345\$US\$ACME\x01",
            ],
        ];
    }
}
