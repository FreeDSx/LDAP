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

use FreeDSx\Ldap\Schema\Validation\Syntax\OidSyntaxValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class OidSyntaxValidatorTest extends TestCase
{
    private OidSyntaxValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new OidSyntaxValidator();
    }

    #[DataProvider('validValuesProvider')]
    public function test_it_accepts_numeric_oids_and_descriptors(string $value): void
    {
        self::assertTrue($this->subject->isValid($value));
    }

    #[DataProvider('invalidValuesProvider')]
    public function test_it_rejects_malformed_oids(string $value): void
    {
        self::assertFalse($this->subject->isValid($value));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validValuesProvider(): array
    {
        return [
            'numeric oid' => ['1.3.6.1.4.1.1466.115.121.1.15'],
            'short numeric oid' => ['2.5.4.3'],
            'descriptor' => ['cn'],
            'descriptor with digits and hyphen' => ['x-my-attr2'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValuesProvider(): array
    {
        return [
            'empty' => [''],
            'leading dot' => ['.1.2'],
            'double dot' => ['1..2'],
            'trailing dot' => ['1.2.'],
            'descriptor starting with digit' => ['1cn'],
            'descriptor with underscore' => ['cn_x'],
            'with space' => ['1.2 3'],
            'trailing newline' => ["1.2.3\n"],
        ];
    }
}
