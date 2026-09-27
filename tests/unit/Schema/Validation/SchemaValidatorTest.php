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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\MatchingRule;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\IndexableComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Rule\InvocationOrder;
use PHPUnit\Framework\TestCase;

final class SchemaValidatorTest extends TestCase
{
    private SchemaValidator $subject;

    protected function setUp(): void
    {
        $this->subject = new SchemaValidator(
            SchemaResource::Core->load(),
            SchemaValidationMode::Strict,
        );
    }

    public function test_mode_returns_configured_mode(): void
    {
        self::assertSame(
            SchemaValidationMode::Strict,
            $this->subject->mode(),
        );
        self::assertSame(
            SchemaValidationMode::Lenient,
            (new SchemaValidator(
                SchemaResource::Core->load(),
                SchemaValidationMode::Lenient,
            ))->mode(),
        );
    }

    public function test_valid_add_passes(): void
    {
        $this->expectNotToPerformAssertions();
        $this->subject->validateAdd($this->personEntry());
    }

    public function test_add_beyond_the_default_value_limit_is_refused(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->expectExceptionMessage('Attribute "gadgetPlain" holds 4 values, which is beyond the limit of 3.');

        $this->gadgetValidator(3)->validateAdd(
            $this->gadgetEntry(new Attribute('gadgetPlain', ...self::values(4))),
        );
    }

    public function test_add_at_the_default_value_limit_passes(): void
    {
        $this->expectNotToPerformAssertions();

        $this->gadgetValidator(3)->validateAdd(
            $this->gadgetEntry(new Attribute('gadgetPlain', ...self::values(3))),
        );
    }

    public function test_a_type_declaring_a_stricter_cap_is_refused_below_the_default(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->expectExceptionMessage('Attribute "gadgetStricter" holds 2 values, which is beyond the limit of 1.');

        $this->gadgetValidator(3)->validateAdd(
            $this->gadgetEntry(new Attribute('gadgetStricter', ...self::values(2))),
        );
    }

    public function test_a_type_declaring_a_looser_cap_passes_above_the_default(): void
    {
        $this->expectNotToPerformAssertions();

        $this->gadgetValidator(3)->validateAdd(
            $this->gadgetEntry(new Attribute('gadgetLooser', ...self::values(6))),
        );
    }

    public function test_a_type_declaring_a_looser_cap_is_still_refused_beyond_it(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->gadgetValidator(3)->validateAdd(
            $this->gadgetEntry(new Attribute('gadgetLooser', ...self::values(7))),
        );
    }

    public function test_a_type_declaring_a_zero_cap_is_unbounded(): void
    {
        $this->expectNotToPerformAssertions();

        $this->gadgetValidator(3)->validateAdd(
            $this->gadgetEntry(new Attribute('gadgetUnbounded', ...self::values(50))),
        );
    }

    public function test_an_option_bearing_form_is_held_to_the_cap_of_the_type_it_subtypes(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->expectExceptionMessage('Attribute "gadgetStricter" holds 2 values, which is beyond the limit of 1.');

        $this->gadgetValidator(3)->validateAdd(
            $this->gadgetEntry(new Attribute('gadgetStricter;lang-en', ...self::values(2))),
        );
    }

    public function test_a_linked_attribute_is_not_bounded(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = new SchemaValidator(
            SchemaResource::Core->load(),
            SchemaValidationMode::Strict,
            maxValues: 3,
        );

        $validator->validateAdd(new Entry(
            new Dn('cn=Team,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'groupOfNames'),
            new Attribute('cn', 'Team'),
            new Attribute('member', ...array_map(
                static fn(int $i): string => "cn=user$i,dc=example,dc=com",
                range(1, 50),
            )),
        ));
    }

    public function test_a_system_write_is_still_bounded(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->gadgetValidator(3)->validateAdd(
            $this->gadgetEntry(new Attribute('gadgetPlain', ...self::values(4))),
            isSystem: true,
        );
    }

    public function test_a_modify_crossing_the_value_limit_is_refused(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $result = $this->gadgetEntry(new Attribute('gadgetPlain', ...self::values(4)));

        $this->gadgetValidator(3)->validateModify(
            new UpdateCommand(
                $result->getDn(),
                [Change::add(new Attribute('gadgetPlain', 'value 4'))],
            ),
            $result,
        );
    }

    public function test_a_modify_staying_within_the_value_limit_passes(): void
    {
        $this->expectNotToPerformAssertions();

        $result = $this->gadgetEntry(new Attribute('gadgetPlain', ...self::values(3)));

        $this->gadgetValidator(3)->validateModify(
            new UpdateCommand(
                $result->getDn(),
                [Change::add(new Attribute('gadgetPlain', 'value 3'))],
            ),
            $result,
        );
    }

    #[DataProvider('unmatchableNamingAttributeProvider')]
    public function test_add_named_by_a_type_with_no_equality_rule_throws_naming_violation(string $dn): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NAMING_VIOLATION);

        $this->subject->validateAdd($this->personEntry($dn));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unmatchableNamingAttributeProvider(): iterable
    {
        yield 'single valued rdn' => [
            'jpegPhoto=zz,dc=example,dc=com',
        ];
        // Every component of a multi-valued RDN names the entry, so one unmatchable component is enough.
        yield 'multi valued rdn, unmatchable component second' => [
            'cn=Alice+jpegPhoto=zz,dc=example,dc=com',
        ];
        yield 'multi valued rdn, unmatchable component first' => [
            'jpegPhoto=zz+cn=Alice,dc=example,dc=com',
        ];
    }

    public function test_add_named_by_a_type_inheriting_its_equality_rule_passes(): void
    {
        $this->expectNotToPerformAssertions();

        // cn declares no EQUALITY of its own and inherits one from name through SUP.
        $this->subject->validateAdd($this->personEntry('cn=Alice,dc=example,dc=com'));
    }

    public function test_add_below_an_ancestor_named_by_an_unmatchable_type_passes(): void
    {
        $this->expectNotToPerformAssertions();

        // Only the leftmost RDN names this entry; the ancestor was its own add's problem.
        $this->subject->validateAdd($this->personEntry('cn=Alice,jpegPhoto=zz,dc=example,dc=com'));
    }

    public function test_rename_onto_a_type_with_no_equality_rule_throws_naming_violation(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NAMING_VIOLATION);

        $this->subject->validateModifyDn(
            $this->personEntry('jpegPhoto=zz,dc=example,dc=com'),
            new Rdn('jpegPhoto', 'zz'),
        );
    }

    /**
     * A group is allowed to hold no members, so that one can be created before its members and survive their removal.
     */
    public function test_add_accepts_a_group_holding_no_members(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->validateAdd(new Entry(
            new Dn('cn=empty,dc=example,dc=com'),
            new Attribute('objectClass', 'groupOfNames'),
            new Attribute('cn', 'empty'),
        ));
    }

    public function test_add_missing_structural_class_throws_object_class_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top'),
            new Attribute('cn', 'Alice'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->subject->validateAdd($entry);
    }

    public function test_add_missing_must_attribute_throws_object_class_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->subject->validateAdd($entry);
    }

    public function test_add_disallowed_attribute_throws_object_class_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('employeeNumber', '42'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->subject->validateAdd($entry);
    }

    public function test_add_undefined_attribute_type_throws(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('unknownAttr99', 'value'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNDEFINED_ATTRIBUTE_TYPE);

        $this->subject->validateAdd($entry);
    }

    public function test_add_single_valued_violation_throws_constraint_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person', 'organizationalPerson', 'inetOrgPerson'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('employeeNumber', '001', '002'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->subject->validateAdd($entry);
    }

    public function test_add_no_user_modification_attribute_throws_constraint_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('createTimestamp', '20240101000000Z'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->subject->validateAdd($entry);
    }

    public function test_add_extensible_object_waives_the_permitted_attribute_list(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person', 'extensibleObject'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            // Defined by the schema but permitted by neither person nor extensibleObject's own MAY list.
            new Attribute('l', 'Somewhere'),
        );

        $this->expectNotToPerformAssertions();
        $this->subject->validateAdd($entry);
    }

    public function test_add_extensible_object_still_requires_a_structural_class(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'extensibleObject'),
            new Attribute('cn', 'Alice'),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->subject->validateAdd($entry);
    }

    public function test_add_extensible_object_still_rejects_an_undefined_attribute_type(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person', 'extensibleObject'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('anyAttr', 'value'),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNDEFINED_ATTRIBUTE_TYPE);

        $this->subject->validateAdd($entry);
    }

    public function test_add_rejects_duplicate_attribute_descriptions(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('CN', 'Other'),
            new Attribute('sn', 'Smith'),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->subject->validateAdd($entry);
    }

    public function test_add_rejects_values_equivalent_under_the_equality_rule(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'SAME', 'same'),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->subject->validateAdd($entry);
    }

    /**
     * The values differ only by case, which caseExactMatch keeps distinct.
     */
    public function test_add_keeps_values_a_case_exact_rule_treats_as_distinct(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'inetOrgPerson'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('labeledURI', 'https://Example.test', 'https://example.test'),
        );

        $this->expectNotToPerformAssertions();
        $this->subject->validateAdd($entry);
    }

    public function test_add_asks_no_equality_of_values_that_cannot_match(): void
    {
        $values = [];
        foreach (range(1, 200) as $i) {
            $values[] = "value {$i}";
        }

        $this->widgetValidator(self::never())->validateAdd(new Entry(
            new Dn('cn=counted,dc=example,dc=com'),
            new Attribute('objectClass', 'widget'),
            new Attribute('widgetLabel', ...$values),
        ));
    }

    public function test_add_asks_equality_only_of_values_sharing_an_index_key(): void
    {
        $values = [];
        foreach (range(1, 199) as $i) {
            $values[] = "value {$i}";
        }
        $values[] = 'VALUE 199';

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->widgetValidator(self::once())->validateAdd(new Entry(
            new Dn('cn=counted,dc=example,dc=com'),
            new Attribute('objectClass', 'widget'),
            new Attribute('widgetLabel', ...$values),
        ));
    }

    public function test_modify_rejects_a_duplicate_the_change_introduces(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=counted,dc=example,dc=com'),
            [Change::add(new Attribute('widgetLabel', 'SAME'))],
        );
        $result = new Entry(
            new Dn('cn=counted,dc=example,dc=com'),
            new Attribute('objectClass', 'widget'),
            new Attribute('widgetLabel', 'same', 'SAME'),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->widgetValidator(self::once())->validateModify($command, $result);
    }

    public function test_modify_leaves_an_attribute_the_change_does_not_touch_unchecked(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=counted,dc=example,dc=com'),
            [Change::replace(new Attribute('widgetNote', 'after'))],
        );
        $result = new Entry(
            new Dn('cn=counted,dc=example,dc=com'),
            new Attribute('objectClass', 'widget'),
            new Attribute('widgetNote', 'after'),
            new Attribute('widgetLabel', 'same', 'SAME'),
        );

        $this->widgetValidator(self::never())->validateModify($command, $result);
    }

    public function test_valid_modify_passes(): void
    {
        $this->expectNotToPerformAssertions();

        $command = new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [Change::replace(new Attribute('sn', 'Jones'))],
        );
        $result = $this->personEntry();

        $this->subject->validateModify($command, $result);
    }

    public function test_modify_rejects_changing_the_structural_object_class(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=group,dc=example,dc=com'),
            [Change::replace(new Attribute('objectClass', 'groupOfUniqueNames'))],
        );
        $result = new Entry(
            new Dn('cn=group,dc=example,dc=com'),
            new Attribute('objectClass', 'groupOfUniqueNames'),
            new Attribute('cn', 'group'),
            new Attribute('uniqueMember', 'cn=someone,dc=example,dc=com'),
            new Attribute('structuralObjectClass', 'groupOfNames'),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::OBJECT_CLASS_MODS_PROHIBITED);

        $this->subject->validateModify($command, $result);
    }

    public function test_modify_keeps_an_unchanged_structural_object_class(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=group,dc=example,dc=com'),
            [Change::add(new Attribute('description', 'A group'))],
        );
        $result = new Entry(
            new Dn('cn=group,dc=example,dc=com'),
            new Attribute('objectClass', 'groupOfNames'),
            new Attribute('cn', 'group'),
            new Attribute('member', 'cn=someone,dc=example,dc=com'),
            new Attribute('description', 'A group'),
            new Attribute('structuralObjectClass', 'groupOfNames'),
        );

        $this->expectNotToPerformAssertions();
        $this->subject->validateModify($command, $result);
    }

    public function test_modify_no_user_modification_attribute_throws_constraint_violation(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [Change::replace(new Attribute('createTimestamp', '20240101000000Z'))],
        );
        $result = $this->personEntry();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->subject->validateModify($command, $result);
    }

    public function test_off_mode_does_not_throw_on_violations(): void
    {
        $subject = new SchemaValidator(
            SchemaResource::Core->load(),
            SchemaValidationMode::Off,
        );

        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top'),
        );

        $this->expectNotToPerformAssertions();
        $subject->validateAdd($entry);
    }

    public function test_system_add_skips_no_user_modification_but_keeps_structure_checks(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('createTimestamp', '20240101000000Z'),
        );

        $this->expectNotToPerformAssertions();

        $this->subject->validateAdd(
            $entry,
            isSystem: true,
        );
    }

    public function test_system_add_still_enforces_structural_class(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->subject->validateAdd(
            $entry,
            isSystem: true,
        );
    }

    public function test_system_modify_skips_no_user_modification_check(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [Change::replace(new Attribute('createTimestamp', '20240101000000Z'))],
        );
        $result = $this->personEntry();

        $this->expectNotToPerformAssertions();

        $this->subject->validateModify(
            $command,
            $result,
            isSystem: true,
        );
    }

    public function test_system_modify_still_enforces_single_valued_attribute(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [Change::replace(new Attribute('createTimestamp', '20240101000000Z', '20240202000000Z'))],
        );
        $result = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('createTimestamp', '20240101000000Z', '20240202000000Z'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->subject->validateModify(
            $command,
            $result,
            isSystem: true,
        );
    }

    public function test_add_invalid_integer_value_throws_invalid_attribute_syntax(): void
    {
        $entry = new Entry(
            new Dn('cn=Widget,dc=example,dc=com'),
            new Attribute('objectClass', 'widget'),
            new Attribute('widgetCount', 'not-a-number'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->syntaxValidator()->validateAdd($entry);
    }

    public function test_add_invalid_distinguished_name_value_throws_invalid_attribute_syntax(): void
    {
        $entry = new Entry(
            new Dn('cn=Widget,dc=example,dc=com'),
            new Attribute('objectClass', 'widget'),
            new Attribute('widgetOwner', 'not a dn'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->syntaxValidator()->validateAdd($entry);
    }

    public function test_add_empty_directory_string_value_throws_invalid_attribute_syntax(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', ''),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->subject->validateAdd($entry);
    }

    public function test_add_with_conforming_values_passes(): void
    {
        $entry = new Entry(
            new Dn('cn=Widget,dc=example,dc=com'),
            new Attribute('objectClass', 'widget'),
            new Attribute('widgetCount', '42'),
            new Attribute('widgetOwner', 'cn=Owner,dc=example,dc=com'),
            new Attribute('widgetSeenAt', '20240101000000Z'),
            new Attribute('widgetActive', 'TRUE'),
        );

        $this->expectNotToPerformAssertions();
        $this->syntaxValidator()->validateAdd($entry);
    }

    public function test_modify_invalid_generalized_time_throws_invalid_attribute_syntax(): void
    {
        $command = new UpdateCommand(
            new Dn('cn=Widget,dc=example,dc=com'),
            [Change::replace(new Attribute('widgetSeenAt', 'not-a-time'))],
        );
        $result = new Entry(
            new Dn('cn=Widget,dc=example,dc=com'),
            new Attribute('objectClass', 'widget'),
            new Attribute('widgetSeenAt', 'not-a-time'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->syntaxValidator()->validateModify(
            $command,
            $result,
        );
    }

    public function test_extensible_object_still_validates_value_syntax(): void
    {
        $entry = new Entry(
            new Dn('cn=Widget,dc=example,dc=com'),
            new Attribute('objectClass', 'extensibleObject'),
            new Attribute('widgetCount', 'not-a-number'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->syntaxValidator()->validateAdd($entry);
    }

    public function test_system_add_still_validates_value_syntax(): void
    {
        $entry = new Entry(
            new Dn('cn=Widget,dc=example,dc=com'),
            new Attribute('objectClass', 'widget'),
            new Attribute('widgetCount', 'not-a-number'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->syntaxValidator()->validateAdd(
            $entry,
            isSystem: true,
        );
    }

    public function test_add_structural_chain_passes(): void
    {
        $entry = new Entry(
            new Dn('cn=Thing,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'alpha', 'alphaChild'),
        );

        $this->expectNotToPerformAssertions();
        $this->structuralChainValidator()->validateAdd($entry);
    }

    public function test_add_two_unrelated_structural_classes_throws_object_class_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Thing,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'alpha', 'beta'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->structuralChainValidator()->validateAdd($entry);
    }

    /**
     * A schema whose gadget attributes declare their own caps, so a test can pit one against the default.
     */
    private function gadgetValidator(int $maxValues): SchemaValidator
    {
        $schema = (new Schema())
            ->addAttributeType(new AttributeType(
                '1.5',
                ['objectClass'],
                syntaxOid: SyntaxOid::OID_OID,
            ))
            ->addAttributeType(new AttributeType(
                '1.30',
                ['gadgetPlain'],
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
            ))
            ->addAttributeType(new AttributeType(
                '1.31',
                ['gadgetStricter'],
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                extensions: [AttributeType::EXTENSION_MAX_VALUES => ['1']],
            ))
            ->addAttributeType(new AttributeType(
                '1.32',
                ['gadgetLooser'],
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                extensions: [AttributeType::EXTENSION_MAX_VALUES => ['6']],
            ))
            ->addAttributeType(new AttributeType(
                '1.33',
                ['gadgetUnbounded'],
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
                extensions: [AttributeType::EXTENSION_MAX_VALUES => ['0']],
            ))
            ->addObjectClass(new ObjectClass(
                '2.30',
                ['gadget'],
                ObjectClassType::StructuralClass,
                must: ['objectClass'],
                may: ['gadgetPlain', 'gadgetStricter', 'gadgetLooser', 'gadgetUnbounded'],
            ));

        return new SchemaValidator(
            $schema,
            SchemaValidationMode::Strict,
            maxValues: $maxValues,
        );
    }

    private function gadgetEntry(Attribute ...$attributes): Entry
    {
        return new Entry(
            new Dn('cn=gadget,dc=example,dc=com'),
            new Attribute('objectClass', 'gadget'),
            ...$attributes,
        );
    }

    /**
     * @return list<string>
     */
    private static function values(int $count): array
    {
        return array_map(
            static fn(int $i): string => "value $i",
            range(1, $count),
        );
    }

    private function personEntry(string $dn = 'cn=Alice,dc=example,dc=com'): Entry
    {
        return new Entry(
            new Dn($dn),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
        );
    }

    private function syntaxValidator(): SchemaValidator
    {
        $schema = (new Schema())
            ->addAttributeType(new AttributeType(
                '1.5',
                ['objectClass'],
                syntaxOid: SyntaxOid::OID_OID,
            ))
            ->addAttributeType(new AttributeType(
                '1.10',
                ['widgetCount'],
                syntaxOid: SyntaxOid::OID_INTEGER,
            ))
            ->addAttributeType(new AttributeType(
                '1.11',
                ['widgetOwner'],
                syntaxOid: SyntaxOid::OID_DISTINGUISHED_NAME,
            ))
            ->addAttributeType(new AttributeType(
                '1.12',
                ['widgetSeenAt'],
                syntaxOid: SyntaxOid::OID_GENERALIZED_TIME,
            ))
            ->addAttributeType(new AttributeType(
                '1.13',
                ['widgetActive'],
                syntaxOid: SyntaxOid::OID_BOOLEAN,
            ))
            ->addObjectClass(new ObjectClass(
                '2.10',
                ['widget'],
                ObjectClassType::StructuralClass,
                must: ['objectClass'],
                may: ['widgetCount', 'widgetOwner', 'widgetSeenAt', 'widgetActive'],
            ));

        return new SchemaValidator(
            $schema,
            SchemaValidationMode::Strict,
        );
    }

    /**
     * A caseIgnore rule expecting a given number of equality questions from the validator.
     */
    private function comparatorExpecting(
        InvocationOrder $equalityCalls,
    ): MatchingRuleComparatorInterface&IndexableComparatorInterface {
        $inner = new CaseIgnoreComparator();

        /** @var MatchingRuleComparatorInterface&IndexableComparatorInterface&MockObject $comparator */
        $comparator = $this->createMockForIntersectionOfInterfaces([
            MatchingRuleComparatorInterface::class,
            IndexableComparatorInterface::class,
        ]);
        $comparator->expects($equalityCalls)
            ->method('equals')
            ->willReturnCallback($inner->equals(...));
        $comparator->method('indexKey')
            ->willReturnCallback($inner->indexKey(...));

        return $comparator;
    }

    /**
     * A schema whose widget attributes carry a rule the test can bound the equality cost of.
     */
    private function widgetValidator(InvocationOrder $equalityCalls): SchemaValidator
    {
        $schema = (new Schema())
            ->addMatchingRule(new MatchingRule(
                '1.900',
                ['widgetMatch'],
                SyntaxOid::OID_DIRECTORY_STRING,
                $this->comparatorExpecting($equalityCalls),
            ))
            ->addAttributeType(new AttributeType(
                '1.5',
                ['objectClass'],
                syntaxOid: SyntaxOid::OID_OID,
            ))
            ->addAttributeType(new AttributeType(
                '1.20',
                ['widgetLabel'],
                equalityOid: '1.900',
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
            ))
            ->addAttributeType(new AttributeType(
                '1.21',
                ['widgetNote'],
                equalityOid: '1.900',
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
            ))
            ->addObjectClass(new ObjectClass(
                '2.20',
                ['widget'],
                ObjectClassType::StructuralClass,
                must: ['objectClass'],
                may: ['widgetLabel', 'widgetNote'],
            ));

        return new SchemaValidator(
            $schema,
            SchemaValidationMode::Strict,
        );
    }

    private function structuralChainValidator(): SchemaValidator
    {
        $schema = (new Schema())
            ->addAttributeType(new AttributeType(
                '1.5',
                ['objectClass'],
            ))
            ->addObjectClass(new ObjectClass(
                '2.0',
                ['top'],
                ObjectClassType::AbstractClass,
                must: ['objectClass'],
            ))
            ->addObjectClass(new ObjectClass(
                '2.1',
                ['alpha'],
                ObjectClassType::StructuralClass,
                superClassOids: ['2.0'],
            ))
            ->addObjectClass(new ObjectClass(
                '2.2',
                ['alphaChild'],
                ObjectClassType::StructuralClass,
                superClassOids: ['2.1'],
            ))
            ->addObjectClass(new ObjectClass(
                '2.3',
                ['beta'],
                ObjectClassType::StructuralClass,
                superClassOids: ['2.0'],
            ));

        return new SchemaValidator(
            $schema,
            SchemaValidationMode::Strict,
        );
    }
}
