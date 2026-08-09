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

use FreeDSx\Ldap\Schema\Validation\Syntax\GeneralizedTimeSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class GeneralizedTimeSyntaxValidatorTest extends TestCase
{
    private GeneralizedTimeSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new GeneralizedTimeSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_valid_generalized_time(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_invalid_generalized_time(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'utc' => ['20240101123000Z'],
            'numeric offset' => ['20240101123000+0500'],
            'hour precision' => ['2024010112Z'],
            'fractional seconds' => ['20240101123000.5Z'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'empty' => [''],
            'year only' => ['2024'],
            'not a time' => ['notatime'],
            'missing zone' => ['20240101123000'],
            'invalid month' => ['20241301010000Z'],
            'trailing newline' => ["20240101123000Z\n"],
        ];
    }
}
