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
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end enforcement of what the shipped schema declares, under Strict validation.
 */
final class LdapSchemaConstraintTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            ['--validation-mode=strict'],
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

    public function test_add_with_invalid_attribute_syntax_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=bad-syntax,dc=foo,dc=bar',
            [
                'cn' => 'bad-syntax',
                'sn' => 'Smith',
                'objectClass' => 'person',
                'seeAlso' => 'not a dn',
            ],
        ));
    }

    public function test_the_published_subschema_declares_entry_uuid_with_the_uuid_syntax(): void
    {
        $this->authenticateAdmin();

        $subschema = $this->ldapClient()->read(
            'cn=Subschema',
            ['attributeTypes'],
        );
        $definitions = $subschema?->get('attributeTypes')?->getValues() ?? [];
        $entryUuid = array_values(array_filter(
            $definitions,
            static fn(string $definition): bool => str_contains($definition, "NAME 'entryUUID'"),
        ));

        self::assertCount(1, $entryUuid);
        self::assertStringContainsString(
            'SYNTAX 1.3.6.1.1.16.1',
            $entryUuid[0],
            'RFC 4530 section 2.1 defines entryUUID with the UUID syntax, not Octet String.',
        );
    }

    /**
     * RFC 4514 permits optional whitespace around the separator, so the same name may be spelled several ways.
     */
    public function test_the_subschema_is_reachable_by_an_equivalent_spelling_of_its_dn(): void
    {
        $this->authenticateAdmin();

        $subschema = $this->ldapClient()->read(
            'cn = Subschema',
            ['subschemaSubentry'],
        );

        self::assertSame(
            ['cn=Subschema'],
            $subschema?->get('subschemaSubentry')?->getValues(),
        );
    }

    public function test_the_subschema_entry_names_itself_as_its_own_subschema(): void
    {
        $this->authenticateAdmin();

        $subschema = $this->ldapClient()->read(
            'cn=Subschema',
            ['subschemaSubentry'],
        );

        self::assertSame(
            ['cn=Subschema'],
            $subschema?->get('subschemaSubentry')?->getValues(),
        );
    }

    public function test_the_subschema_entry_carries_a_structural_class_and_satisfies_its_must(): void
    {
        $this->authenticateAdmin();

        $subschema = $this->ldapClient()->read(
            'cn=Subschema',
            [
                'objectClass',
                'structuralObjectClass',
                'cn',
                'subtreeSpecification',
            ],
        );

        self::assertNotNull($subschema);
        self::assertSame(
            [
                'top',
                'subentry',
                'subschema',
            ],
            $subschema->get('objectClass')?->getValues(),
        );
        self::assertSame(
            ['subentry'],
            $subschema->get('structuralObjectClass')?->getValues(),
        );
        self::assertSame(
            ['{ }'],
            $subschema->get('subtreeSpecification')?->getValues(),
        );
    }

    public function test_the_subschema_entry_answers_a_filter_on_its_structural_class(): void
    {
        $this->authenticateAdmin();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('objectClass', 'subentry'))
                ->base('cn=Subschema')
                ->useBaseScope(),
        );

        self::assertCount(1, $entries);
    }

    #[DataProvider('telephoneNumberProvider')]
    public function test_telephone_number_is_constrained_to_printable_characters(
        string $value,
        bool $isValid,
    ): void {
        $this->authenticateAdmin();

        if (!$isValid) {
            $this->expectException(OperationException::class);
            $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);
        }

        $this->ldapClient()->create(Entry::fromArray(
            'cn=tel-' . md5($value) . ',dc=foo,dc=bar',
            [
                'cn' => 'tel-' . md5($value),
                'sn' => 'Smith',
                'objectClass' => 'inetOrgPerson',
                'telephoneNumber' => $value,
            ],
        ));

        self::assertTrue($isValid);
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function telephoneNumberProvider(): iterable
    {
        yield 'an E.123 number' => [
            '+1 512 315 0280',
            true,
        ];
        // RFC 4517 3.3.31 constrains only the encoding, which E.123 formatting is a subset of.
        yield 'printable but not a number' => [
            'not-a-phone-number',
            true,
        ];
        yield 'non-printable ascii' => [
            'abc!@#$%',
            false,
        ];
        yield 'non-ascii' => [
            'h3llo-wörld',
            false,
        ];
    }

    public function test_add_named_by_an_attribute_with_no_equality_rule_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NAMING_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'jpegPhoto=zz,dc=foo,dc=bar',
            [
                'sn' => 'Smith',
                'objectClass' => 'inetOrgPerson',
                'cn' => 'no-equality',
            ],
        ));
    }

    public function test_rename_onto_an_attribute_with_no_equality_rule_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=to-rename-naming,dc=foo,dc=bar',
            [
                'cn' => 'to-rename-naming',
                'sn' => 'Smith',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NAMING_VIOLATION);

        $this->ldapClient()->rename(
            'cn=to-rename-naming,dc=foo,dc=bar',
            'jpegPhoto=zz',
            false,
        );
    }

    public function test_add_supplies_the_superclasses_of_the_named_object_classes(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=superclasses,dc=foo,dc=bar',
            [
                'cn' => 'superclasses',
                'sn' => 'Smith',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        self::assertSame(
            [
                'inetOrgPerson',
                'organizationalPerson',
                'person',
                'top',
            ],
            $this->ldapClient()
                ->read('cn=superclasses,dc=foo,dc=bar', ['objectClass'])
                ?->get('objectClass')
                ?->getValues(),
        );
    }

    /**
     * The point of supplying them: a filter naming a superclass finds an entry that named only the subclass.
     */
    #[DataProvider('superclassFilterProvider')]
    public function test_a_filter_naming_a_superclass_finds_the_entry(string $objectClass): void
    {
        $this->authenticateAdmin();

        $cn = 'bysuperclass-' . strtolower($objectClass);
        $dn = "cn=$cn,dc=foo,dc=bar";

        $this->ldapClient()->create(Entry::fromArray(
            $dn,
            [
                'cn' => $cn,
                'sn' => 'Smith',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('objectClass', $objectClass))
                ->base($dn)
                ->useBaseScope(),
        );

        self::assertCount(1, $entries);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function superclassFilterProvider(): iterable
    {
        yield 'the named class' => ['inetOrgPerson'];
        yield 'its immediate superclass' => ['organizationalPerson'];
        yield 'a class further up the chain' => ['person'];
        yield 'the abstract root' => ['top'];
    }

    public function test_add_omitting_the_naming_attribute_still_stores_it(): void
    {
        $this->authenticateAdmin();

        // RFC 4511 section 4.7 lets a client leave the RDN attribute out of the attribute list.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=implied-cn,dc=foo,dc=bar',
            [
                'sn' => 'Smith',
                'objectClass' => 'person',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'implied-cn'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'implied-cn',
            $entries->first()?->get('cn')?->firstValue(),
        );
    }

    public function test_add_with_an_empty_directory_string_value_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        // 'sn' is a Directory String, which RFC 4517 defines as one or more characters.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=empty-surname,dc=foo,dc=bar',
            [
                'cn' => 'empty-surname',
                'sn' => '',
                'objectClass' => 'person',
            ],
        ));
    }

    public function test_modify_setting_an_empty_directory_string_value_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=empty-description,dc=foo,dc=bar',
            [
                'cn' => 'empty-description',
                'sn' => 'Smith',
                'objectClass' => 'person',
            ],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $entry = Entry::fromArray('cn=empty-description,dc=foo,dc=bar');
        $entry->set('description', '');
        $this->ldapClient()->update($entry);
    }

    public function test_add_with_two_unrelated_structural_classes_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=two-structural,dc=foo,dc=bar',
            [
                'cn' => 'two-structural',
                'sn' => 'Smith',
                'ou' => 'People',
                'objectClass' => ['person', 'organizationalUnit'],
            ],
        ));
    }

    public function test_add_missing_a_required_attribute_of_a_built_in_class_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        // 'sn' is MUST on the 'person' class.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=no-surname,dc=foo,dc=bar',
            [
                'cn' => 'no-surname',
                'objectClass' => 'person',
            ],
        ));
    }

    public function test_modify_adding_an_attribute_the_class_does_not_permit_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=strict-modify,dc=foo,dc=bar',
            [
                'cn' => 'strict-modify',
                'sn' => 'Smith',
                'objectClass' => 'person',
            ],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        // 'mail' is neither MUST nor MAY on 'person'.
        $entry = Entry::fromArray('cn=strict-modify,dc=foo,dc=bar');
        $entry->set('mail', 'strict-modify@foo.bar');
        $this->ldapClient()->update($entry);
    }

    public function test_add_with_two_values_for_a_single_valued_attribute_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        // 'displayName' is SINGLE-VALUE.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=two-display-names,dc=foo,dc=bar',
            [
                'cn' => 'two-display-names',
                'sn' => 'Smith',
                'objectClass' => 'inetOrgPerson',
                'displayName' => ['First', 'Second'],
            ],
        ));
    }

    public function test_modify_adding_a_second_value_to_a_single_valued_attribute_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=single-value-modify,dc=foo,dc=bar',
            [
                'cn' => 'single-value-modify',
                'sn' => 'Smith',
                'objectClass' => 'inetOrgPerson',
                'displayName' => 'First',
            ],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $entry = Entry::fromArray('cn=single-value-modify,dc=foo,dc=bar');
        $entry->add('displayName', 'Second');
        $this->ldapClient()->update($entry);
    }

    public function test_add_writing_a_no_user_modification_attribute_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        // 'createTimestamp' is NO-USER-MODIFICATION; the server maintains it.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=client-timestamp,dc=foo,dc=bar',
            [
                'cn' => 'client-timestamp',
                'sn' => 'Smith',
                'objectClass' => 'person',
                'createTimestamp' => '20200101000000Z',
            ],
        ));
    }

    public function test_modify_writing_a_no_user_modification_attribute_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=operational-modify,dc=foo,dc=bar',
            [
                'cn' => 'operational-modify',
                'sn' => 'Smith',
                'objectClass' => 'person',
            ],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $entry = Entry::fromArray('cn=operational-modify,dc=foo,dc=bar');
        $entry->set('modifiersName', 'cn=someone,dc=foo,dc=bar');
        $this->ldapClient()->update($entry);
    }

    public function test_add_with_a_non_numeric_value_for_an_integer_attribute_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        // 'gidNumber' declares the INTEGER syntax.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=bad-gid,dc=foo,dc=bar',
            [
                'cn' => 'bad-gid',
                'objectClass' => 'posixGroup',
                'gidNumber' => 'not-a-number',
            ],
        ));
    }

    public function test_add_with_a_non_boolean_value_for_a_boolean_attribute_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        // 'pwdLockout' declares the BOOLEAN syntax, which permits only TRUE or FALSE.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=bad-boolean,dc=foo,dc=bar',
            [
                'cn' => 'bad-boolean',
                'sn' => 'Smith',
                'objectClass' => ['person', 'pwdPolicy'],
                'pwdAttribute' => 'userPassword',
                'pwdLockout' => 'maybe',
            ],
        ));
    }

    public function test_the_nis_schema_is_usable_end_to_end(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=posix-users,dc=foo,dc=bar',
            [
                'cn' => 'posix-users',
                'objectClass' => 'posixGroup',
                'gidNumber' => '5000',
                'memberUid' => ['alice', 'bob'],
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('gidNumber', '5000'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'posix-users',
            $entries->first()?->get('cn')?->firstValue(),
        );
    }

    public function test_a_posix_group_missing_its_required_gid_is_rejected(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        // 'gidNumber' is MUST on 'posixGroup'.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=no-gid,dc=foo,dc=bar',
            [
                'cn' => 'no-gid',
                'objectClass' => 'posixGroup',
            ],
        ));
    }

    /**
     * RFC 4519 3.10, whose MAY list is what pulled the remaining core attribute types into the schema.
     */
    public function test_an_organizational_role_is_accepted_with_its_optional_attributes(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=helpdesk,dc=foo,dc=bar',
            [
                'cn' => 'helpdesk',
                'objectClass' => 'organizationalRole',
                'roleOccupant' => 'cn=admin,dc=foo,dc=bar',
                'preferredDeliveryMethod' => 'telephone',
                'facsimileTelephoneNumber' => '+1 555 555 1234$fineResolution',
                'telexNumber' => '12345$US$ACME',
                'postalAddress' => '1234 Main St.$Anytown, CA 12345$USA',
                'teletexTerminalIdentifier' => 'term1$graphic:on',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'helpdesk'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            'cn=admin,dc=foo,dc=bar',
            $entries->first()?->get('roleOccupant')?->firstValue(),
        );
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function invalidCoreSyntaxProvider(): array
    {
        return [
            'a delivery method outside the keywords' => [
                'preferredDeliveryMethod',
                'carrier-pigeon',
            ],
            'a fax parameter outside the keywords' => [
                'facsimileTelephoneNumber',
                '+1 555 555 1234$bogusParam',
            ],
            'a telex number missing a component' => [
                'telexNumber',
                '12345$US',
            ],
            'a postal address with a bare backslash' => [
                'postalAddress',
                'a\b',
            ],
            'a teletex key outside the keywords' => [
                'teletexTerminalIdentifier',
                'term1$bogus:x',
            ],
        ];
    }

    #[DataProvider('invalidCoreSyntaxProvider')]
    public function test_a_value_the_new_core_syntaxes_reject_is_refused(
        string $attribute,
        string $value,
    ): void {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=bad-core-syntax,dc=foo,dc=bar',
            [
                'cn' => 'bad-core-syntax',
                'objectClass' => 'organizationalRole',
                $attribute => $value,
            ],
        ));
    }

    /**
     * RFC 5234 2.3 makes the quoted ABNF literals case-insensitive, which other implementations allow.
     */
    public function test_a_keyword_in_another_case_is_accepted(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=mixed-case-keyword,dc=foo,dc=bar',
            [
                'cn' => 'mixed-case-keyword',
                'objectClass' => 'organizationalRole',
                'preferredDeliveryMethod' => 'Telephone',
                'facsimileTelephoneNumber' => '+1 555 555 1234$FineResolution',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'mixed-case-keyword'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            1,
            $entries,
        );
    }
}
