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

namespace Tests\Unit\FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\SchemaLoadMode;
use FreeDSx\Ldap\Schema\StandardSchemaProvider;
use FreeDSx\Ldap\Schema\SubschemaLoader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SubschemaLoaderTest extends TestCase
{
    /**
     * A subschema captured from the OpenLDAP container in tests/resources/openldap.
     */
    private const OPENLDAP_FIXTURE = __DIR__ . '/../../resources/schema/openldap-subschema.ldif';

    /**
     * A subschema captured from the OpenDJ container in tests/profile.
     */
    private const OPENDJ_FIXTURE = __DIR__ . '/../../resources/schema/opendj-subschema.ldif';

    private SubschemaLoader $subject;

    protected function setUp(): void
    {
        $this->subject = new SubschemaLoader();
    }

    public function test_it_reads_a_subschema_entry(): void
    {
        $schema = $this->subject->fromLdifString($this->subschemaLdif(
            "attributeTypes: ( 1.3.6.1.4.1.99999.1.1 NAME 'vendorTicket' "
            . 'SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )',
        ));

        $attr = $schema->getAttributeType('vendorTicket');

        self::assertNotNull($attr);
        self::assertSame(
            '1.3.6.1.4.1.99999.1.1',
            $attr->oid,
        );
        self::assertTrue($attr->singleValue);
    }

    public function test_it_reads_an_entry_directly(): void
    {
        $entry = Entry::fromArray('cn=Subschema', [
            'objectClasses' => ["( 1.3.6.1.4.1.99999.2.1 NAME 'vendorRecord' AUXILIARY )"],
        ]);

        $class = $this->subject->fromEntry($entry)
            ->getObjectClass('vendorRecord');

        self::assertNotNull($class);
        self::assertSame(
            ObjectClassType::AuxiliaryClass,
            $class->type,
        );
    }

    public function test_folded_lines_are_joined(): void
    {
        $ldif = "dn: cn=Subschema\n"
            . "attributeTypes: ( 1.3.6.1.4.1.99999.1.1 NAME 'vendorTicket' DESC 'a folded des\n"
            . " cription' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n";

        self::assertSame(
            'a folded description',
            $this->subject->fromLdifString($ldif)
                ->getAttributeType('vendorTicket')?->desc,
        );
    }

    public function test_it_throws_when_the_source_has_no_entry(): void
    {
        $this->expectException(SchemaParseException::class);

        $this->subject->fromLdifString('');
    }

    public function test_the_mode_reaches_the_entry_parser(): void
    {
        $ldif = $this->subschemaLdif("attributeTypes: ( 2.5.4.3 NAME 'cn' BOGUS )");

        self::assertSame(
            [],
            (new SubschemaLoader(SchemaLoadMode::Lenient))->fromLdifString($ldif)
                ->getAttributeTypes(),
        );

        $this->expectException(SchemaParseException::class);
        $this->subject->fromLdifString($ldif);
    }

    public function test_a_subschema_this_library_publishes_loads_in_strict_mode(): void
    {
        $core = StandardSchemaProvider::buildCore();

        $loaded = $this->subject->fromLdifString($this->publishedSubschema());

        foreach ($core->getAttributeTypes() as $type) {
            self::assertSame(
                $type->toDescriptionString(),
                $loaded->getAttributeType($type->oid)?->toDescriptionString(),
            );
        }

        foreach ($core->getObjectClasses() as $class) {
            self::assertSame(
                $class->toDescriptionString(),
                $loaded->getObjectClass($class->oid)?->toDescriptionString(),
            );
        }
    }

    /**
     * @return array<string, array{string, SchemaLoadMode, int, int}>
     */
    public static function vendorSubschemaProvider(): array
    {
        return [
            'openldap' => [self::OPENLDAP_FIXTURE, SchemaLoadMode::Lenient, 250, 50],
            'opendj' => [self::OPENDJ_FIXTURE, SchemaLoadMode::Strict, 1000, 300],
        ];
    }

    #[DataProvider('vendorSubschemaProvider')]
    public function test_a_real_subschema_parses_completely(
        string $fixture,
        SchemaLoadMode $mode,
        int $leastAttributeTypes,
        int $leastObjectClasses,
    ): void {
        $schema = (new SubschemaLoader($mode))->fromLdifFile($fixture);

        self::assertGreaterThan(
            $leastAttributeTypes,
            count($schema->getAttributeTypes()),
        );
        self::assertGreaterThan(
            $leastObjectClasses,
            count($schema->getObjectClasses()),
        );
    }

    #[DataProvider('vendorSubschemaProvider')]
    public function test_a_real_subschema_yields_the_definitions_every_server_ships(
        string $fixture,
        SchemaLoadMode $mode,
    ): void {
        $schema = (new SubschemaLoader($mode))->fromLdifFile($fixture);

        self::assertNotNull($schema->getAttributeType('cn'));
        self::assertNotNull($schema->getAttributeType('userPassword'));
        self::assertNotNull($schema->getObjectClass('inetOrgPerson'));
    }

    #[DataProvider('vendorSubschemaProvider')]
    public function test_a_real_subschema_reads_space_separated_names(
        string $fixture,
        SchemaLoadMode $mode,
    ): void {
        $schema = (new SubschemaLoader($mode))->fromLdifFile($fixture);

        self::assertSame(
            ['cn', 'commonName'],
            $schema->getAttributeType('cn')?->names,
        );
    }

    #[DataProvider('vendorSubschemaProvider')]
    public function test_a_real_subschema_never_yields_matching_rules(
        string $fixture,
        SchemaLoadMode $mode,
    ): void {
        $schema = (new SubschemaLoader($mode))->fromLdifFile($fixture);

        self::assertSame(
            [],
            $schema->getMatchingRules(),
        );
    }

    /**
     * Publishing ldapSyntaxes is optional per RFC 4512 §4.2, so whether a server is self-consistent varies.
     *
     * @return array<string, array{string, bool}>
     */
    public static function strictAcceptanceProvider(): array
    {
        return [
            'openldap uses syntaxes it does not declare' => [self::OPENLDAP_FIXTURE, false],
            'opendj declares every syntax it uses' => [self::OPENDJ_FIXTURE, true],
        ];
    }

    #[DataProvider('strictAcceptanceProvider')]
    public function test_strict_acceptance_of_a_real_subschema(
        string $fixture,
        bool $isAccepted,
    ): void {
        if (!$isAccepted) {
            $this->expectException(SchemaParseException::class);
        }

        $schema = $this->subject->fromLdifFile($fixture);

        self::assertNotEmpty($schema->getAttributeTypes());
    }

    public function test_openldap_syntax_length_bounds_are_discarded(): void
    {
        $schema = (new SubschemaLoader(SchemaLoadMode::Lenient))->fromLdifFile(self::OPENLDAP_FIXTURE);

        self::assertSame(
            '1.3.6.1.4.1.1466.115.121.1.15',
            $schema->getAttributeType('supportedSASLMechanisms')?->syntaxOid,
        );
    }

    public function test_opendj_definitions_keep_every_extension(): void
    {
        $uid = $this->subject->fromLdifFile(self::OPENDJ_FIXTURE)
            ->getAttributeType('uid');

        self::assertSame(
            [
                'X-ORIGIN' => ['RFC 4519'],
                'X-SCHEMA-FILE' => ['00-core.ldif'],
            ],
            $uid?->extensions,
        );
    }

    private function subschemaLdif(string ...$definitions): string
    {
        return "dn: cn=Subschema\n" . implode("\n", $definitions) . "\n";
    }

    /**
     * Renders the standard schema the way ServerSubschemaHandler publishes it.
     */
    private function publishedSubschema(): string
    {
        $core = StandardSchemaProvider::buildCore();
        $lines = ['dn: cn=Subschema'];

        foreach ($core->getLdapSyntaxes() as $syntax) {
            $lines[] = 'ldapSyntaxes: ' . $syntax->toDescriptionString();
        }
        foreach ($core->getAttributeTypes() as $type) {
            $lines[] = 'attributeTypes: ' . $type->toDescriptionString();
        }
        foreach ($core->getObjectClasses() as $class) {
            $lines[] = 'objectClasses: ' . $class->toDescriptionString();
        }
        foreach ($core->getMatchingRules() as $rule) {
            $lines[] = 'matchingRules: ' . $rule->toDescriptionString();
        }

        return implode("\n", $lines) . "\n";
    }
}
