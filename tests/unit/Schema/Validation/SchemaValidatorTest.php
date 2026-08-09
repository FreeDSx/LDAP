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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
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

    public function test_add_extensible_object_bypasses_attribute_checks(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'extensibleObject'),
            new Attribute('anyAttr', 'value'),
        );

        $this->expectNotToPerformAssertions();
        $this->subject->validateAdd($entry);
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
