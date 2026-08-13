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

namespace Tests\Integration\FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * A schema parsed from LDIF drives validation exactly as one built in PHP does.
 */
final class LdapLoadedSchemaTest extends ServerTestCase
{
    private const SCHEMA_LDIF = __DIR__ . '/../../resources/schema/custom-subschema.ldif';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            ['--schema-ldif=' . self::SCHEMA_LDIF],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    public function test_an_entry_using_a_loaded_object_class_is_accepted(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=loaded-ok,dc=foo,dc=bar',
            [
                'cn' => 'loaded-ok',
                'objectClass' => 'projectRecord',
                'projectCode' => 'apollo',
                'projectNotes' => 'from a loaded schema',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'loaded-ok'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'apollo',
            $entries->first()?->get('projectCode')?->firstValue(),
        );
    }

    public function test_a_loaded_object_class_enforces_its_required_attributes(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        // 'projectCode' is MUST on the loaded 'projectRecord' class.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=loaded-missing-must,dc=foo,dc=bar',
            [
                'cn' => 'loaded-missing-must',
                'objectClass' => 'projectRecord',
            ],
        ));
    }

    public function test_a_loaded_object_class_rejects_an_attribute_it_does_not_permit(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        // 'sn' is neither MUST nor MAY on the loaded 'projectRecord' class.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=loaded-extra-attr,dc=foo,dc=bar',
            [
                'cn' => 'loaded-extra-attr',
                'objectClass' => 'projectRecord',
                'projectCode' => 'gemini',
                'sn' => 'Nope',
            ],
        ));
    }

    public function test_a_loaded_attribute_is_searchable_by_its_matching_rules(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=loaded-search,dc=foo,dc=bar',
            [
                'cn' => 'loaded-search',
                'objectClass' => 'projectRecord',
                'projectCode' => 'Voyager',
            ],
        ));

        // The loaded definition declares caseIgnoreMatch and caseIgnoreSubstringsMatch.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::contains('projectCode', 'oyag'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'loaded-search',
            $entries->first()?->get('cn')?->firstValue(),
        );
    }

    public function test_object_identifier_first_component_matches_by_the_leading_oid(): void
    {
        $this->createRecord(
            'first-component',
            ['projectClassDef' => "( 2.5.6.6 NAME 'person' SUP 2.5.6.0 STRUCTURAL )"],
        );

        self::assertSame(
            'first-component',
            $this->findOne(Filters::equal('projectClassDef', '2.5.6.6')),
        );
    }

    public function test_object_identifier_first_component_ignores_an_oid_appearing_later(): void
    {
        $this->createRecord(
            'first-component-sup',
            ['projectClassDef' => "( 2.5.6.7 NAME 'organization' SUP 2.5.6.0 STRUCTURAL )"],
        );

        // 2.5.6.0 is the SUP, not the first component.
        self::assertNull($this->findOne(Filters::equal('projectClassDef', '2.5.6.0')));
    }

    public function test_integer_first_component_matches_by_the_leading_number(): void
    {
        $this->createRecord(
            'integer-first-component',
            ['projectRuleDef' => "( 12 NAME 'structureRule' FORM nameForm )"],
        );

        self::assertSame(
            'integer-first-component',
            $this->findOne(Filters::equal('projectRuleDef', '12')),
        );
    }

    public function test_numeric_string_treats_spaces_as_insignificant(): void
    {
        $this->createRecord(
            'numeric-string',
            ['projectSerial' => '1 555 867'],
        );

        self::assertSame(
            'numeric-string',
            $this->findOne(Filters::equal('projectSerial', '1555867')),
        );
    }

    public function test_numeric_string_substring_spans_a_space(): void
    {
        $this->createRecord(
            'numeric-string-substring',
            ['projectSerial' => '1 555 867'],
        );

        self::assertSame(
            'numeric-string-substring',
            $this->findOne(Filters::contains('projectSerial', '5558')),
        );
    }

    public function test_bit_string_matches_the_quoted_form(): void
    {
        $this->createRecord(
            'bit-string',
            ['projectFlags' => "'0101'B"],
        );

        self::assertSame(
            'bit-string',
            $this->findOne(Filters::equal('projectFlags', "'0101'B")),
        );
    }

    /**
     * RFC 4517 3.3.2 requires the quoted form, so a bare sequence is an invalid assertion value and is Undefined.
     */
    public function test_bit_string_rejects_a_bare_bit_sequence(): void
    {
        $this->createRecord(
            'bit-string-bare',
            ['projectFlags' => "'0101'B"],
        );

        self::assertNull($this->findOne(Filters::equal('projectFlags', '0101')));
    }

    public function test_bit_string_does_not_match_different_bits(): void
    {
        $this->createRecord(
            'bit-string-differs',
            ['projectFlags' => "'0101'B"],
        );

        self::assertNull($this->findOne(Filters::equal('projectFlags', "'0110'B")));
    }

    public function test_telephone_number_substring_ignores_spaces_and_hyphens(): void
    {
        $this->createRecord(
            'telephone-substring',
            ['projectPhone' => '+1 800 555-1234'],
        );

        self::assertSame(
            'telephone-substring',
            $this->findOne(Filters::contains('projectPhone', '8005551234')),
        );
    }

    public function test_case_ignore_ia5_substring_folds_case(): void
    {
        $this->createRecord(
            'ia5-substring',
            ['projectMail' => 'Alice@Example.COM'],
        );

        self::assertSame(
            'ia5-substring',
            $this->findOne(Filters::contains('projectMail', 'example.com')),
        );
    }

    public function test_case_ignore_list_folds_case(): void
    {
        $this->createRecord(
            'ignore-list',
            ['projectAddress' => '1 High Street$Springfield'],
        );

        self::assertSame(
            'ignore-list',
            $this->findOne(Filters::equal('projectAddress', '1 high street$springfield')),
        );
    }

    public function test_uuid_matches_exactly(): void
    {
        $this->createRecord(
            'uuid-exact',
            ['projectUuid' => '597ae2f6-16a6-1027-98f4-d28b5365dc14'],
        );

        self::assertSame(
            'uuid-exact',
            $this->findOne(Filters::equal('projectUuid', '597ae2f6-16a6-1027-98f4-d28b5365dc14')),
        );
    }

    public function test_a_malformed_uuid_value_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->createRecord(
            'uuid-malformed',
            ['projectUuid' => '597ae2f6-16a6-1027-98f4-not-a-uuid'],
        );
    }

    public function test_an_upper_case_uuid_value_is_accepted(): void
    {
        $this->createRecord(
            'uuid-upper',
            ['projectUuid' => '597AE2F6-16A6-1027-98F4-D28B5365DC14'],
        );

        self::assertSame(
            'uuid-upper',
            $this->findOne(Filters::equal('projectUuid', '597AE2F6-16A6-1027-98F4-D28B5365DC14')),
        );
    }

    public function test_uuid_is_case_sensitive(): void
    {
        $this->createRecord(
            'uuid-case',
            ['projectUuid' => '597ae2f6-16a6-1027-98f4-d28b5365dc14'],
        );

        // RFC 4530 defines uuidMatch as octetStringMatch, so case-insensitive matching would be wrong.
        self::assertNull($this->findOne(Filters::equal('projectUuid', '597AE2F6-16A6-1027-98F4-D28B5365DC14')));
    }

    public function test_the_standard_schema_still_applies_alongside_loaded_definitions(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=loaded-standard,dc=foo,dc=bar',
            [
                'cn' => 'loaded-standard',
                'sn' => 'Standard',
                'objectClass' => 'person',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'loaded-standard'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
    }

    /**
     * @param array<string, string> $attributes
     */
    private function createRecord(
        string $cn,
        array $attributes,
    ): void {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            "cn={$cn},dc=foo,dc=bar",
            [
                'cn' => $cn,
                'objectClass' => 'projectRecord',
                'projectCode' => 'Matching',
                ...$attributes,
            ],
        ));
    }

    /**
     * The cn of the single matching entry, or null when the filter matches nothing.
     */
    private function findOne(FilterInterface $filter): ?string
    {
        $entries = $this->ldapClient()->search(
            Operations::search($filter)
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        return $entries->first()
            ?->get('cn')
            ?->firstValue();
    }
}
