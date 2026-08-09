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

use FreeDSx\Ldap\Schema\Validation\Syntax\UuidSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class UuidSyntaxValidatorTest extends TestCase
{
    private UuidSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new UuidSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_well_formed_uuids(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_malformed_uuids(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'lower case' => ['597ae2f6-16a6-1027-98f4-d28b5365dc14'],
            'upper case' => ['597AE2F6-16A6-1027-98F4-D28B5365DC14'],
            'mixed case' => ['597ae2f6-16A6-1027-98f4-D28B5365dc14'],
            'nil uuid' => ['00000000-0000-0000-0000-000000000000'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'empty' => [''],
            'no dashes' => ['597ae2f616a6102798f4d28b5365dc14'],
            'wrong group lengths' => ['597ae2f-616a6-1027-98f4-d28b5365dc14'],
            'too short' => ['597ae2f6-16a6-1027-98f4-d28b5365dc1'],
            'too long' => ['597ae2f6-16a6-1027-98f4-d28b5365dc145'],
            'non hex digit' => ['597ae2g6-16a6-1027-98f4-d28b5365dc14'],
            'leading space' => [' 597ae2f6-16a6-1027-98f4-d28b5365dc14'],
            'trailing newline' => ["597ae2f6-16a6-1027-98f4-d28b5365dc14\n"],
            'braced form' => ['{597ae2f6-16a6-1027-98f4-d28b5365dc14}'],
        ];
    }
}
