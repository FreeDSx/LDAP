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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Parser\SubschemaEntryParser;
use FreeDSx\Ldap\Schema\SchemaLoadMode;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\SchemaReferenceValidator;
use PHPUnit\Framework\TestCase;

final class SubschemaEntryParserTest extends TestCase
{
    private SubschemaEntryParser $subject;

    protected function setUp(): void
    {
        $this->subject = new SubschemaEntryParser(
            references: new SchemaReferenceValidator(SchemaResource::Core->load()),
        );
    }

    public function test_it_reads_each_kind_of_definition(): void
    {
        $schema = $this->subject->parse(
            $this->entry([
                'ldapSyntaxes' => ["( 1.3.6.1.4.1.99999.3.1 DESC 'Vendor Syntax' )"],
                'attributeTypes' => ["( 1.3.6.1.4.1.99999.1.1 NAME 'vendorTicket' SYNTAX 1.3.6.1.4.1.99999.3.1 )"],
                'objectClasses' => ["( 1.3.6.1.4.1.99999.2.1 NAME 'vendorRecord' MUST vendorTicket )"],
            ]),
            SchemaLoadMode::Strict,
        );

        self::assertNotNull($schema->getSyntax('1.3.6.1.4.1.99999.3.1'));
        self::assertNotNull($schema->getAttributeType('vendorTicket'));
        self::assertNotNull($schema->getObjectClass('vendorRecord'));
    }

    public function test_an_empty_entry_yields_an_empty_schema(): void
    {
        $schema = $this->subject->parse(
            $this->entry([]),
            SchemaLoadMode::Strict,
        );

        self::assertSame(
            [],
            $schema->getAttributeTypes(),
        );
        self::assertSame(
            [],
            $schema->getObjectClasses(),
        );
    }

    public function test_a_matching_rule_is_read_when_a_comparator_implements_it(): void
    {
        $schema = $this->subject->parse(
            $this->entry([
                'matchingRules' => ["( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"],
            ]),
            SchemaLoadMode::Strict,
        );

        $rule = $schema->getMatchingRule('2.5.13.2');

        self::assertNotNull($rule);
        self::assertSame(
            ['caseIgnoreMatch'],
            $rule->names,
        );
        self::assertInstanceOf(
            CaseIgnoreComparator::class,
            $rule->comparator,
        );
    }

    public function test_a_matching_rule_without_a_comparator_is_skipped(): void
    {
        $schema = $this->subject->parse(
            $this->entry([
                'matchingRules' => ["( 2.5.13.32 NAME 'wordMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"],
            ]),
            SchemaLoadMode::Strict,
        );

        self::assertSame(
            [],
            $schema->getMatchingRules(),
        );
    }

    public function test_matching_rule_use_is_not_read(): void
    {
        $schema = $this->subject->parse(
            $this->entry([
                'matchingRuleUse' => ["( 2.5.13.2 NAME 'caseIgnoreMatch' APPLIES cn )"],
            ]),
            SchemaLoadMode::Strict,
        );

        self::assertSame(
            [],
            $schema->getMatchingRules(),
        );
    }

    public function test_an_unknown_matching_rule_reference_is_kept_and_never_fails(): void
    {
        $schema = $this->subject->parse(
            $this->entry([
                'attributeTypes' => [
                    "( 1.3.6.1.4.1.99999.1.3 NAME 'vendorRank' EQUALITY 2.5.13.8 "
                    . 'SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )',
                ],
            ]),
            SchemaLoadMode::Strict,
        );

        self::assertSame(
            '2.5.13.8',
            $schema->getAttributeType('vendorRank')?->equalityOid,
        );
    }

    public function test_definitions_resolve_against_each_other(): void
    {
        $schema = $this->subject->parse(
            $this->entry([
                'attributeTypes' => ["( 1.3.6.1.4.1.99999.1.1 NAME 'vendorTicket' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"],
                'objectClasses' => ["( 1.3.6.1.4.1.99999.2.1 NAME 'vendorRecord' MUST vendorTicket )"],
            ]),
            SchemaLoadMode::Strict,
        );

        self::assertSame(
            ['vendorTicket'],
            $schema->getObjectClass('vendorRecord')?->must,
        );
    }

    public function test_definitions_resolve_against_the_standard_schema(): void
    {
        $schema = $this->subject->parse(
            $this->entry([
                'objectClasses' => ["( 1.3.6.1.4.1.99999.2.1 NAME 'vendorRecord' SUP top MUST cn )"],
            ]),
            SchemaLoadMode::Strict,
        );

        self::assertSame(
            ['cn'],
            $schema->getObjectClass('vendorRecord')?->must,
        );
    }

    public function test_strict_rejects_a_malformed_definition(): void
    {
        $this->expectException(SchemaParseException::class);

        $this->subject->parse(
            $this->entry(['attributeTypes' => ["( 2.5.4.3 NAME 'cn' BOGUS )"]]),
            SchemaLoadMode::Strict,
        );
    }

    public function test_lenient_skips_only_the_malformed_definition(): void
    {
        $schema = $this->subject->parse(
            $this->entry([
                'attributeTypes' => [
                    "( 2.5.4.3 NAME 'cn' BOGUS )",
                    "( 2.5.4.4 NAME 'sn' )",
                ],
            ]),
            SchemaLoadMode::Lenient,
        );

        self::assertNull($schema->getAttributeType('cn'));
        self::assertNotNull($schema->getAttributeType('sn'));
    }

    public function test_strict_rejects_an_unresolvable_reference(): void
    {
        $this->expectException(SchemaParseException::class);

        $this->subject->parse(
            $this->entry([
                'objectClasses' => ["( 1.3.6.1.4.1.99999.2.1 NAME 'vendorRecord' MUST nosuchattr )"],
            ]),
            SchemaLoadMode::Strict,
        );
    }

    public function test_lenient_keeps_a_definition_with_an_unresolvable_reference(): void
    {
        $schema = $this->subject->parse(
            $this->entry([
                'objectClasses' => ["( 1.3.6.1.4.1.99999.2.1 NAME 'vendorRecord' MUST nosuchattr )"],
            ]),
            SchemaLoadMode::Lenient,
        );

        self::assertSame(
            ['nosuchattr'],
            $schema->getObjectClass('vendorRecord')?->must,
        );
    }

    /**
     * @param array<string, list<string>> $attributes
     */
    private function entry(array $attributes): Entry
    {
        return Entry::fromArray(
            'cn=Subschema',
            $attributes,
        );
    }
}
