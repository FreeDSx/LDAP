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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Validation;

use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\LdapSyntax;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaLoadMode;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\SchemaReferenceValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SchemaReferenceValidatorTest extends TestCase
{
    private SchemaReferenceValidator $subject;

    protected function setUp(): void
    {
        // No base, so a definition resolves only against the schema it is checked with.
        $this->subject = new SchemaReferenceValidator(new Schema());
    }

    public function test_a_schema_with_resolvable_references_passes(): void
    {
        $this->expectNotToPerformAssertions();

        $schema = (new Schema())
            ->addSyntax(new LdapSyntax('1.3.6.1.4.1.99999.3.1'))
            ->addAttributeType(new AttributeType(
                oid: '1.3.6.1.4.1.99999.1.1',
                names: ['vendorTicket'],
                syntaxOid: '1.3.6.1.4.1.99999.3.1',
            ))
            ->addObjectClass(new ObjectClass(
                oid: '1.3.6.1.4.1.99999.2.1',
                names: ['vendorRecord'],
                must: ['vendorTicket'],
            ));

        $this->subject->validate(
            $schema,
            SchemaLoadMode::Strict,
        );
    }

    /**
     * @return array<string, array{Schema}>
     */
    public static function unresolvableProvider(): array
    {
        return [
            'attribute type with an unknown superior' => [
                (new Schema())->addAttributeType(new AttributeType(
                    oid: '1.3.6.1.4.1.99999.1.1',
                    names: ['vendorTicket'],
                    superTypeOid: 'nosuchattr',
                )),
            ],
            'attribute type with an unknown syntax' => [
                (new Schema())->addAttributeType(new AttributeType(
                    oid: '1.3.6.1.4.1.99999.1.1',
                    names: ['vendorTicket'],
                    syntaxOid: '1.3.6.1.4.1.99999.9.9',
                )),
            ],
            'object class with an unknown superior' => [
                (new Schema())->addObjectClass(new ObjectClass(
                    oid: '1.3.6.1.4.1.99999.2.1',
                    names: ['vendorRecord'],
                    superClassOids: ['nosuchclass'],
                )),
            ],
            'object class with an unknown required attribute' => [
                (new Schema())->addObjectClass(new ObjectClass(
                    oid: '1.3.6.1.4.1.99999.2.1',
                    names: ['vendorRecord'],
                    must: ['nosuchattr'],
                )),
            ],
            'object class with an unknown optional attribute' => [
                (new Schema())->addObjectClass(new ObjectClass(
                    oid: '1.3.6.1.4.1.99999.2.1',
                    names: ['vendorRecord'],
                    may: ['nosuchattr'],
                )),
            ],
        ];
    }

    #[DataProvider('unresolvableProvider')]
    public function test_strict_rejects_an_unresolvable_reference(Schema $schema): void
    {
        $this->expectException(SchemaParseException::class);

        $this->subject->validate(
            $schema,
            SchemaLoadMode::Strict,
        );
    }

    #[DataProvider('unresolvableProvider')]
    public function test_lenient_accepts_an_unresolvable_reference(Schema $schema): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->validate(
            $schema,
            SchemaLoadMode::Lenient,
        );
    }

    /**
     * An unknown rule falls back to default comparison at filter time, so it must never fail a load.
     */
    public function test_matching_rule_references_are_not_checked(): void
    {
        $this->expectNotToPerformAssertions();

        $schema = (new Schema())->addAttributeType(new AttributeType(
            oid: '1.3.6.1.4.1.99999.1.1',
            names: ['vendorTicket'],
            equalityOid: 'nosuchrule',
            orderingOid: 'nosuchrule',
            substringOid: 'nosuchrule',
        ));

        $this->subject->validate(
            $schema,
            SchemaLoadMode::Strict,
        );
    }

    public function test_the_core_schema_resolves_its_own_references(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->validate(
            SchemaResource::Core->load(),
            SchemaLoadMode::Strict,
        );
    }

    public function test_a_custom_base_schema_is_used_for_resolution(): void
    {
        $this->expectNotToPerformAssertions();

        $base = (new Schema())->addAttributeType(new AttributeType(
            oid: '1.3.6.1.4.1.99999.1.1',
            names: ['vendorTicket'],
        ));
        $schema = (new Schema())->addObjectClass(new ObjectClass(
            oid: '1.3.6.1.4.1.99999.2.1',
            names: ['vendorRecord'],
            must: ['vendorTicket'],
        ));

        (new SchemaReferenceValidator($base))->validate(
            $schema,
            SchemaLoadMode::Strict,
        );
    }
}
