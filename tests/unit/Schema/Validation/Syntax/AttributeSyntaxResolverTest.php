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
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use PHPUnit\Framework\TestCase;

final class AttributeSyntaxResolverTest extends TestCase
{
    private AttributeSyntaxResolver $subject;

    protected function setUp(): void
    {
        $this->subject = new AttributeSyntaxResolver(SchemaResource::Core->load());
    }

    public function test_a_value_conforms_to_a_syntax_named_directly(): void
    {
        self::assertTrue($this->subject->conformsToSyntax(
            SyntaxOid::OID_INTEGER,
            '-42',
        ));
        self::assertFalse($this->subject->conformsToSyntax(
            SyntaxOid::OID_INTEGER,
            '+42',
        ));
    }

    public function test_a_syntax_without_a_validator_accepts_any_value(): void
    {
        self::assertTrue($this->subject->conformsToSyntax(
            '1.2.3.4.5.6',
            'anything',
        ));
    }
}
