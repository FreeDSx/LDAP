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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Parser;

use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Parser\SchemaDefinitionParser;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SchemaDefinitionParserTest extends TestCase
{
    private SchemaDefinitionParser $subject;

    protected function setUp(): void
    {
        $this->subject = new SchemaDefinitionParser();
    }

    public function test_attribute_type_minimal(): void
    {
        $attr = $this->subject->parseAttributeType("( 2.5.4.3 NAME 'cn' )");

        self::assertSame(
            '2.5.4.3',
            $attr->oid,
        );
        self::assertSame(
            ['cn'],
            $attr->names,
        );
        self::assertSame(
            AttributeUsage::UserApplications,
            $attr->usage,
        );
    }

    public function test_attribute_type_with_alias_list(): void
    {
        $attr = $this->subject->parseAttributeType("( 2.5.4.3 NAME ( 'cn' 'commonName' ) )");

        self::assertSame(
            ['cn', 'commonName'],
            $attr->names,
        );
    }

    public function test_attribute_type_with_all_oid_fields(): void
    {
        $attr = $this->subject->parseAttributeType(
            "( 2.5.4.3 NAME 'cn' DESC 'common name' SUP 2.5.4.41 EQUALITY 2.5.13.2 ORDERING 2.5.13.3 "
            . 'SUBSTR 2.5.13.4 SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )',
        );

        self::assertSame(
            'common name',
            $attr->desc,
        );
        self::assertSame(
            '2.5.4.41',
            $attr->superTypeOid,
        );
        self::assertSame(
            '2.5.13.2',
            $attr->equalityOid,
        );
        self::assertSame(
            '2.5.13.3',
            $attr->orderingOid,
        );
        self::assertSame(
            '2.5.13.4',
            $attr->substringOid,
        );
        self::assertSame(
            '1.3.6.1.4.1.1466.115.121.1.15',
            $attr->syntaxOid,
        );
    }

    public function test_attribute_type_flags(): void
    {
        $attr = $this->subject->parseAttributeType(
            "( 2.5.4.3 NAME 'cn' OBSOLETE SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION )",
        );

        self::assertTrue($attr->obsolete);
        self::assertTrue($attr->singleValue);
        self::assertTrue($attr->collective);
        self::assertTrue($attr->noUserModification);
    }

    public function test_attribute_type_flags_default_to_false(): void
    {
        $attr = $this->subject->parseAttributeType("( 2.5.4.3 NAME 'cn' )");

        self::assertFalse($attr->obsolete);
        self::assertFalse($attr->singleValue);
        self::assertFalse($attr->collective);
        self::assertFalse($attr->noUserModification);
    }

    public function test_syntax_length_bound_is_discarded(): void
    {
        $attr = $this->subject->parseAttributeType(
            "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} )",
        );

        self::assertSame(
            '1.3.6.1.4.1.1466.115.121.1.15',
            $attr->syntaxOid,
        );
    }

    /**
     * @return array<string, array{string, AttributeUsage}>
     */
    public static function usageProvider(): array
    {
        return [
            'user applications' => ['userApplications', AttributeUsage::UserApplications],
            'directory operation' => ['directoryOperation', AttributeUsage::DirectoryOperation],
            'distributed operation' => ['distributedOperation', AttributeUsage::DistributedOperation],
            'dsa operation' => ['dSAOperation', AttributeUsage::DsaOperation],
            'dsa operation in lower case' => ['dsaoperation', AttributeUsage::DsaOperation],
            'directory operation in upper case' => ['DIRECTORYOPERATION', AttributeUsage::DirectoryOperation],
        ];
    }

    #[DataProvider('usageProvider')]
    public function test_attribute_type_usage(
        string $value,
        AttributeUsage $expected,
    ): void {
        $attr = $this->subject->parseAttributeType("( 2.5.4.3 NAME 'cn' USAGE $value )");

        self::assertSame(
            $expected,
            $attr->usage,
        );
    }

    public function test_attribute_type_with_unknown_usage_throws(): void
    {
        $this->expectException(SchemaParseException::class);

        $this->subject->parseAttributeType("( 2.5.4.3 NAME 'cn' USAGE nonsense )");
    }

    public function test_keywords_are_matched_without_regard_to_case(): void
    {
        $attr = $this->subject->parseAttributeType("( 2.5.4.3 name 'cn' single-value )");

        self::assertSame(
            ['cn'],
            $attr->names,
        );
        self::assertTrue($attr->singleValue);
    }

    public function test_keywords_may_appear_in_any_order(): void
    {
        $attr = $this->subject->parseAttributeType(
            "( 2.5.4.3 SINGLE-VALUE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 NAME 'cn' DESC 'a name' )",
        );

        self::assertSame(
            ['cn'],
            $attr->names,
        );
        self::assertSame(
            'a name',
            $attr->desc,
        );
        self::assertTrue($attr->singleValue);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function spacingProvider(): array
    {
        return [
            'canonical' => ["( 2.5.4.3 NAME 'cn' )"],
            'no space after the opening paren' => ["(2.5.4.3 NAME 'cn' )"],
            'no space before the closing paren' => ["( 2.5.4.3 NAME 'cn')"],
            'no padding at all' => ["(2.5.4.3 NAME 'cn')"],
            'runs of spaces' => ["(    2.5.4.3     NAME      'cn'    )"],
            'tabs and newlines' => ["(\n\t2.5.4.3\n\tNAME 'cn'\n)"],
            'surrounded by whitespace' => ["   ( 2.5.4.3 NAME 'cn' )   "],
        ];
    }

    #[DataProvider('spacingProvider')]
    public function test_spacing_between_tokens_is_not_significant(string $definition): void
    {
        $attr = $this->subject->parseAttributeType($definition);

        self::assertSame(
            '2.5.4.3',
            $attr->oid,
        );
        self::assertSame(
            ['cn'],
            $attr->names,
        );
    }

    /**
     * RFC 4512 §1.4 separates a qdescrlist by space, but this library previously wrote "$", so both are read.
     *
     * @return array<string, array{string}>
     */
    public static function nameListProvider(): array
    {
        return [
            'space separated per rfc 4512' => ["( 'cn' 'commonName' )"],
            'dollar separated' => ["( 'cn' \$ 'commonName' )"],
            'no space around the dollar' => ["( 'cn'\$'commonName' )"],
            'no padding inside the parens' => ["('cn' 'commonName')"],
            'runs of whitespace' => ["(   'cn'    'commonName'   )"],
        ];
    }

    #[DataProvider('nameListProvider')]
    public function test_name_list_separators(string $names): void
    {
        $attr = $this->subject->parseAttributeType("( 2.5.4.3 NAME $names )");

        self::assertSame(
            ['cn', 'commonName'],
            $attr->names,
        );
    }

    public function test_oid_list_is_dollar_separated(): void
    {
        $class = $this->subject->parseObjectClass('( 2.5.6.6 MUST ( sn $ cn ) )');

        self::assertSame(
            ['sn', 'cn'],
            $class->must,
        );
    }

    public function test_empty_name_list_is_allowed(): void
    {
        $attr = $this->subject->parseAttributeType('( 2.5.4.3 NAME () )');

        self::assertSame(
            [],
            $attr->names,
        );
    }

    public function test_empty_oid_list_throws(): void
    {
        $this->expectException(SchemaParseException::class);

        $this->subject->parseObjectClass('( 2.5.6.6 MUST () )');
    }

    public function test_syntax_length_bound_against_the_closing_paren(): void
    {
        $attr = $this->subject->parseAttributeType('( 2.5.4.3 SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64})');

        self::assertSame(
            '1.3.6.1.4.1.1466.115.121.1.15',
            $attr->syntaxOid,
        );
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function escapeProvider(): array
    {
        return [
            'escaped quote as written by this library' => ["'it\\'s'", "it's"],
            'escaped backslash as written by this library' => ["'a\\\\b'", 'a\\b'],
            'hex escaped quote per rfc 4512' => ["'it\\27s'", "it's"],
            'hex escaped backslash per rfc 4512' => ["'a\\5Cb'", 'a\\b'],
            'lower case hex escape' => ["'a\\5cb'", 'a\\b'],
            'no escapes' => ["'plain'", 'plain'],
        ];
    }

    #[DataProvider('escapeProvider')]
    public function test_description_escapes(
        string $quoted,
        string $expected,
    ): void {
        $attr = $this->subject->parseAttributeType("( 2.5.4.3 NAME 'cn' DESC $quoted )");

        self::assertSame(
            $expected,
            $attr->desc,
        );
    }

    public function test_extensions_are_kept(): void
    {
        $attr = $this->subject->parseAttributeType("( 2.5.4.35 NAME 'userPassword' X-CONFIDENTIAL 'TRUE' )");

        self::assertSame(
            [AttributeType::EXTENSION_CONFIDENTIAL => ['TRUE']],
            $attr->extensions,
        );
        self::assertTrue($attr->isConfidential());
    }

    public function test_extensions_with_multiple_values(): void
    {
        $attr = $this->subject->parseAttributeType("( 2.5.4.3 NAME 'cn' X-ORIGIN ( 'RFC 4519' \$ 'RFC 4512' ) )");

        self::assertSame(
            ['X-ORIGIN' => ['RFC 4519', 'RFC 4512']],
            $attr->extensions,
        );
    }

    public function test_extension_with_an_unquoted_value(): void
    {
        $attr = $this->subject->parseAttributeType("( 2.5.4.3 NAME 'cn' X-ORDERED VALUES )");

        self::assertSame(
            ['X-ORDERED' => ['VALUES']],
            $attr->extensions,
        );
    }

    public function test_object_class_minimal_defaults_to_structural(): void
    {
        $class = $this->subject->parseObjectClass("( 2.5.6.6 NAME 'person' )");

        self::assertSame(
            ObjectClassType::StructuralClass,
            $class->type,
        );
    }

    /**
     * @return array<string, array{string, ObjectClassType}>
     */
    public static function objectClassTypeProvider(): array
    {
        return [
            'structural' => ['STRUCTURAL', ObjectClassType::StructuralClass],
            'auxiliary' => ['AUXILIARY', ObjectClassType::AuxiliaryClass],
            'abstract' => ['ABSTRACT', ObjectClassType::AbstractClass],
        ];
    }

    #[DataProvider('objectClassTypeProvider')]
    public function test_object_class_type(
        string $keyword,
        ObjectClassType $expected,
    ): void {
        $class = $this->subject->parseObjectClass("( 2.5.6.6 NAME 'person' $keyword )");

        self::assertSame(
            $expected,
            $class->type,
        );
    }

    public function test_object_class_with_more_than_one_type_throws(): void
    {
        $this->expectException(SchemaParseException::class);

        $this->subject->parseObjectClass("( 2.5.6.6 NAME 'person' STRUCTURAL AUXILIARY )");
    }

    public function test_object_class_with_full_body(): void
    {
        $class = $this->subject->parseObjectClass(
            "( 2.5.6.6 NAME 'person' DESC 'natural persons' SUP top STRUCTURAL MUST ( sn \$ cn ) MAY description )",
        );

        self::assertSame(
            'natural persons',
            $class->desc,
        );
        self::assertSame(
            ['top'],
            $class->superClassOids,
        );
        self::assertSame(
            ['sn', 'cn'],
            $class->must,
        );
        self::assertSame(
            ['description'],
            $class->may,
        );
    }

    public function test_object_class_with_multiple_superiors(): void
    {
        $class = $this->subject->parseObjectClass("( 2.5.6.6 NAME 'person' SUP ( top \$ 2.5.6.0 ) )");

        self::assertSame(
            ['top', '2.5.6.0'],
            $class->superClassOids,
        );
    }

    public function test_ldap_syntax(): void
    {
        $syntax = $this->subject->parseLdapSyntax(
            "( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' X-ORIGIN 'RFC 4517' )",
        );

        self::assertSame(
            '1.3.6.1.4.1.1466.115.121.1.15',
            $syntax->oid,
        );
        self::assertSame(
            'Directory String',
            $syntax->desc,
        );
        self::assertSame(
            ['X-ORIGIN' => ['RFC 4517']],
            $syntax->extensions,
        );
    }

    public function test_ldap_syntax_without_a_description(): void
    {
        $syntax = $this->subject->parseLdapSyntax('( 1.3.6.1.4.1.1466.115.121.1.40 )');

        self::assertNull($syntax->desc);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedProvider(): array
    {
        return [
            'missing opening paren' => ["2.5.4.3 NAME 'cn' )"],
            'missing closing paren' => ["( 2.5.4.3 NAME 'cn'"],
            'unknown keyword' => ["( 2.5.4.3 NAME 'cn' BOGUS )"],
            'duplicate keyword' => ["( 2.5.4.3 NAME 'cn' NAME 'commonName' )"],
            'duplicate flag' => ["( 2.5.4.3 NAME 'cn' SINGLE-VALUE SINGLE-VALUE )"],
            'duplicate extension' => ["( 2.5.4.3 X-ORIGIN 'a' X-ORIGIN 'b' )"],
            'descriptor instead of a numeric oid' => ["( cn NAME 'cn' )"],
            'numeric oid without a dot' => ["( 2 NAME 'cn' )"],
            'unterminated quoted string' => ["( 2.5.4.3 NAME 'cn )"],
            'content after the definition' => ["( 2.5.4.3 NAME 'cn' ) trailing"],
            'empty definition' => [''],
            'missing value for a keyword' => ['( 2.5.4.3 NAME )'],
            'unterminated list' => ["( 2.5.4.3 NAME ( 'cn'"],
            'nested list' => ["( 2.5.4.3 NAME ( ( 'cn' ) ) )"],
            'separator with no item' => ["( 2.5.4.3 NAME ( \$ ) )"],
        ];
    }

    #[DataProvider('malformedProvider')]
    public function test_malformed_attribute_type_throws(string $definition): void
    {
        $this->expectException(SchemaParseException::class);

        $this->subject->parseAttributeType($definition);
    }

    public function test_exception_carries_the_definition_and_offset(): void
    {
        try {
            $this->subject->parseAttributeType("( 2.5.4.3 NAME 'cn' BOGUS )");
            self::fail('Expected a SchemaParseException.');
        } catch (SchemaParseException $e) {
            self::assertSame(
                "( 2.5.4.3 NAME 'cn' BOGUS )",
                $e->getDefinition(),
            );
            self::assertSame(
                25,
                $e->getOffset(),
            );
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function shippedAttributeTypeProvider(): array
    {
        $definitions = [];

        foreach (self::shippedSchemas() as $label => $schema) {
            foreach ($schema->getAttributeTypes() as $type) {
                $definitions["$label: " . ($type->names[0] ?? $type->oid)] = [$type->toDescriptionString()];
            }
        }

        return $definitions;
    }

    #[DataProvider('shippedAttributeTypeProvider')]
    public function test_every_shipped_attribute_type_round_trips(string $definition): void
    {
        self::assertSame(
            $definition,
            $this->subject->parseAttributeType($definition)
                ->toDescriptionString(),
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function shippedObjectClassProvider(): array
    {
        $definitions = [];

        foreach (self::shippedSchemas() as $label => $schema) {
            foreach ($schema->getObjectClasses() as $class) {
                $definitions["$label: " . ($class->names[0] ?? $class->oid)] = [$class->toDescriptionString()];
            }
        }

        return $definitions;
    }

    #[DataProvider('shippedObjectClassProvider')]
    public function test_every_shipped_object_class_round_trips(string $definition): void
    {
        self::assertSame(
            $definition,
            $this->subject->parseObjectClass($definition)
                ->toDescriptionString(),
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function shippedLdapSyntaxProvider(): array
    {
        $definitions = [];

        foreach (self::shippedSchemas() as $label => $schema) {
            foreach ($schema->getLdapSyntaxes() as $syntax) {
                $definitions["$label: $syntax->oid"] = [$syntax->toDescriptionString()];
            }
        }

        return $definitions;
    }

    #[DataProvider('shippedLdapSyntaxProvider')]
    public function test_every_shipped_ldap_syntax_round_trips(string $definition): void
    {
        self::assertSame(
            $definition,
            $this->subject->parseLdapSyntax($definition)
                ->toDescriptionString(),
        );
    }

    public function test_confidentiality_survives_a_round_trip(): void
    {
        $userPassword = SchemaResource::Core->load()
            ->getAttributeType(AttributeTypeOid::NAME_USER_PASSWORD);

        self::assertNotNull($userPassword);
        self::assertTrue($userPassword->isConfidential());

        $parsed = $this->subject->parseAttributeType($userPassword->toDescriptionString());

        self::assertTrue($parsed->isConfidential());
    }

    /**
     * @return array<string, Schema>
     */
    private static function shippedSchemas(): array
    {
        return [
            'standard' => SchemaResource::Core->load(),
            'nis' => SchemaResource::Nis->load(),
            'ppolicy' => SchemaResource::PasswordPolicy->load(),
        ];
    }
}
