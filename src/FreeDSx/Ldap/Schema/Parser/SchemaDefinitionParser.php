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

namespace FreeDSx\Ldap\Schema\Parser;

use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Definition\DefinitionKeyword;
use FreeDSx\Ldap\Schema\Definition\LdapSyntax;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;

use function count;
use function sprintf;
use function strcasecmp;

/**
 * Parses RFC 4512 description strings into schema definitions; the inverse of toDescriptionString().
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SchemaDefinitionParser
{
    /**
     * @var array<string, KeywordKind>
     */
    private const ATTRIBUTE_TYPE_KEYWORDS = [
        DefinitionKeyword::NAME => KeywordKind::QdStrings,
        DefinitionKeyword::DESC => KeywordKind::QdString,
        DefinitionKeyword::OBSOLETE => KeywordKind::Flag,
        DefinitionKeyword::SUP => KeywordKind::Oid,
        DefinitionKeyword::EQUALITY => KeywordKind::Oid,
        DefinitionKeyword::ORDERING => KeywordKind::Oid,
        DefinitionKeyword::SUBSTR => KeywordKind::Oid,
        DefinitionKeyword::SYNTAX => KeywordKind::Oid,
        DefinitionKeyword::SINGLE_VALUE => KeywordKind::Flag,
        DefinitionKeyword::COLLECTIVE => KeywordKind::Flag,
        DefinitionKeyword::NO_USER_MODIFICATION => KeywordKind::Flag,
        DefinitionKeyword::USAGE => KeywordKind::Oid,
    ];

    /**
     * @var array<string, KeywordKind>
     */
    private const OBJECT_CLASS_KEYWORDS = [
        DefinitionKeyword::NAME => KeywordKind::QdStrings,
        DefinitionKeyword::DESC => KeywordKind::QdString,
        DefinitionKeyword::OBSOLETE => KeywordKind::Flag,
        DefinitionKeyword::SUP => KeywordKind::Oids,
        DefinitionKeyword::MUST => KeywordKind::Oids,
        DefinitionKeyword::MAY => KeywordKind::Oids,
        ObjectClassType::AbstractClass->value => KeywordKind::Flag,
        ObjectClassType::StructuralClass->value => KeywordKind::Flag,
        ObjectClassType::AuxiliaryClass->value => KeywordKind::Flag,
    ];

    /**
     * @var array<string, KeywordKind>
     */
    private const LDAP_SYNTAX_KEYWORDS = [
        DefinitionKeyword::DESC => KeywordKind::QdString,
    ];

    /**
     * @throws SchemaParseException
     */
    public function parseAttributeType(string $definition): AttributeType
    {
        $reader = new SchemaDefinitionReader($definition);
        $oid = $this->readHeader($reader);
        $body = ParsedDefinitionBody::read(
            $reader,
            self::ATTRIBUTE_TYPE_KEYWORDS,
        );
        $this->assertComplete($reader);

        return new AttributeType(
            oid: $oid,
            names: $body->values(DefinitionKeyword::NAME),
            equalityOid: $body->string(DefinitionKeyword::EQUALITY),
            orderingOid: $body->string(DefinitionKeyword::ORDERING),
            substringOid: $body->string(DefinitionKeyword::SUBSTR),
            syntaxOid: $body->string(DefinitionKeyword::SYNTAX),
            singleValue: $body->flag(DefinitionKeyword::SINGLE_VALUE),
            collective: $body->flag(DefinitionKeyword::COLLECTIVE),
            noUserModification: $body->flag(DefinitionKeyword::NO_USER_MODIFICATION),
            usage: $this->usageFrom(
                $reader,
                $body->string(DefinitionKeyword::USAGE),
            ),
            superTypeOid: $body->string(DefinitionKeyword::SUP),
            desc: $body->string(DefinitionKeyword::DESC),
            obsolete: $body->flag(DefinitionKeyword::OBSOLETE),
            extensions: $body->extensions(),
        );
    }

    /**
     * @throws SchemaParseException
     */
    public function parseObjectClass(string $definition): ObjectClass
    {
        $reader = new SchemaDefinitionReader($definition);
        $oid = $this->readHeader($reader);
        $body = ParsedDefinitionBody::read(
            $reader,
            self::OBJECT_CLASS_KEYWORDS,
        );
        $this->assertComplete($reader);

        return new ObjectClass(
            oid: $oid,
            names: $body->values(DefinitionKeyword::NAME),
            type: $this->classTypeFrom(
                $reader,
                $body,
            ),
            superClassOids: $body->values(DefinitionKeyword::SUP),
            must: $body->values(DefinitionKeyword::MUST),
            may: $body->values(DefinitionKeyword::MAY),
            desc: $body->string(DefinitionKeyword::DESC),
            obsolete: $body->flag(DefinitionKeyword::OBSOLETE),
            extensions: $body->extensions(),
        );
    }

    /**
     * @throws SchemaParseException
     */
    public function parseLdapSyntax(string $definition): LdapSyntax
    {
        $reader = new SchemaDefinitionReader($definition);
        $oid = $this->readHeader($reader);
        $body = ParsedDefinitionBody::read(
            $reader,
            self::LDAP_SYNTAX_KEYWORDS,
        );
        $this->assertComplete($reader);

        return new LdapSyntax(
            oid: $oid,
            desc: $body->string(DefinitionKeyword::DESC),
            extensions: $body->extensions(),
        );
    }

    /**
     * @throws SchemaParseException
     */
    private function readHeader(SchemaDefinitionReader $reader): string
    {
        $reader->expect('(');

        return $reader->readNumericOid();
    }

    /**
     * @throws SchemaParseException
     */
    private function assertComplete(SchemaDefinitionReader $reader): void
    {
        if (!$reader->atEnd()) {
            $reader->error('Unexpected content after the definition');
        }
    }

    /**
     * Resolves the USAGE value, which is compared without regard to case since the backing values are mixed-case.
     *
     * @throws SchemaParseException
     */
    private function usageFrom(
        SchemaDefinitionReader $reader,
        ?string $value,
    ): AttributeUsage {
        if ($value === null) {
            return AttributeUsage::UserApplications;
        }

        foreach (AttributeUsage::cases() as $usage) {
            if (strcasecmp($usage->value, $value) === 0) {
                return $usage;
            }
        }

        $reader->error(sprintf(
            'Unknown attribute usage "%s"',
            $value,
        ));
    }

    /**
     * Resolves the object class kind, which defaults to STRUCTURAL when omitted per RFC 4512 §4.1.1.
     *
     * @throws SchemaParseException
     */
    private function classTypeFrom(
        SchemaDefinitionReader $reader,
        ParsedDefinitionBody $body,
    ): ObjectClassType {
        $found = [];

        foreach (ObjectClassType::cases() as $type) {
            if ($body->flag($type->value)) {
                $found[] = $type;
            }
        }

        if (count($found) > 1) {
            $reader->error('Only one of ABSTRACT, STRUCTURAL or AUXILIARY may be given');
        }

        return $found[0] ?? ObjectClassType::StructuralClass;
    }
}
