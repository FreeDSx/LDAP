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

use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Validation\Syntax\BooleanSyntaxValidator;
use FreeDSx\Ldap\Schema\Validation\Syntax\IntegerSyntaxValidator;
use FreeDSx\Ldap\Schema\Validation\Syntax\SyntaxValidatorInterface;
use FreeDSx\Ldap\Schema\Validation\Syntax\SyntaxValidatorRegistry;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SyntaxValidatorRegistryTest extends TestCase
{
    #[DataProvider('constrainedSyntaxProvider')]
    public function test_default_provides_a_validator_for_constrained_syntaxes(string $syntaxOid): void
    {
        self::assertInstanceOf(
            SyntaxValidatorInterface::class,
            SyntaxValidatorRegistry::default()->get($syntaxOid),
        );
    }

    public function test_default_returns_null_for_a_permissive_syntax(): void
    {
        self::assertNull(SyntaxValidatorRegistry::default()->get(SyntaxOid::OID_OCTET_STRING));
    }

    public function test_default_returns_null_for_an_unknown_syntax(): void
    {
        self::assertNull(SyntaxValidatorRegistry::default()->get('1.2.3.4.5.6.7.8.9'));
    }

    public function test_it_uses_the_validators_it_is_constructed_with(): void
    {
        $integer = new IntegerSyntaxValidator();
        $registry = new SyntaxValidatorRegistry([SyntaxOid::OID_INTEGER => $integer]);

        self::assertSame(
            $integer,
            $registry->get(SyntaxOid::OID_INTEGER),
        );
        self::assertNull($registry->get(SyntaxOid::OID_BOOLEAN));
    }

    public function test_default_maps_each_syntax_to_its_matching_validator(): void
    {
        self::assertInstanceOf(
            BooleanSyntaxValidator::class,
            SyntaxValidatorRegistry::default()->get(SyntaxOid::OID_BOOLEAN),
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function constrainedSyntaxProvider(): array
    {
        return [
            'directory string' => [SyntaxOid::OID_DIRECTORY_STRING],
            'integer' => [SyntaxOid::OID_INTEGER],
            'boolean' => [SyntaxOid::OID_BOOLEAN],
            'generalized time' => [SyntaxOid::OID_GENERALIZED_TIME],
            'distinguished name' => [SyntaxOid::OID_DISTINGUISHED_NAME],
            'oid' => [SyntaxOid::OID_OID],
            'numeric string' => [SyntaxOid::OID_NUMERIC_STRING],
            'printable string' => [SyntaxOid::OID_PRINTABLE_STRING],
            'ia5 string' => [SyntaxOid::OID_IA5_STRING],
            'bit string' => [SyntaxOid::OID_BIT_STRING],
        ];
    }
}
