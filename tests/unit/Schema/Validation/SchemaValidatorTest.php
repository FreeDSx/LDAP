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

use Closure;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SchemaValidationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SchemaValidatorTest extends TestCase
{
    use ServerContainerTrait;

    private SchemaValidator $subject;

    protected function setUp(): void
    {
        $this->subject = $this->validatorFor(TestServerOptions::validatedCore(SchemaValidationMode::Strict));
    }

    public function test_mode_returns_configured_mode(): void
    {
        self::assertSame(
            SchemaValidationMode::Strict,
            $this->subject->mode(),
        );
        self::assertSame(
            SchemaValidationMode::Lenient,
            $this->validatorFor(TestServerOptions::validatedCore(SchemaValidationMode::Lenient))->mode(),
        );
    }

    public function test_valid_add_passes(): void
    {
        $this->expectNotToPerformAssertions();
        $this->subject->validate(SchemaWrite::add($this->personEntry()));
    }

    public function test_an_add_reports_every_rule_it_breaks_in_check_order(): void
    {
        $entry = $this->personEntry();
        $entry->add(new Attribute('createTimestamp', '20200101000000Z'));
        $entry->add(new Attribute('description', 'same', 'SAME'));
        $entry->add(new Attribute('mail', 'alice@example.com'));

        try {
            $this->subject->validate(SchemaWrite::add($entry));
            self::fail('The entry breaks three rules and should be refused.');
        } catch (SchemaValidationException $e) {
            self::assertSame(
                [SchemaRule::SettableOperationalAttribute, SchemaRule::EquivalentValues, SchemaRule::AllowedAttributes],
                self::rulesOf($e),
            );
            self::assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }
    }

    public function test_a_modify_reports_every_rule_it_breaks_in_check_order(): void
    {
        $result = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('seeAlso', 'not a dn'),
            new Attribute('modifyTimestamp', '20200101000000Z'),
            new Attribute('description', 'same', 'SAME'),
            new Attribute('mail', 'alice@example.com'),
            new Attribute('structuralObjectClass', 'device'),
        );
        $write = SchemaWrite::modify(
            $result,
            [
                Change::add(new Attribute('seeAlso', 'not a dn')),
                Change::replace(new Attribute('modifyTimestamp', '20200101000000Z')),
                Change::add(new Attribute('description', 'same', 'SAME')),
                Change::add(new Attribute('mail', 'alice@example.com')),
                Change::reset('sn'),
            ],
        );

        try {
            $this->subject->validate($write);
            self::fail('The modify breaks six rules and should be refused.');
        } catch (SchemaValidationException $e) {
            self::assertSame(
                [
                    SchemaRule::AttributeSyntax,
                    SchemaRule::SettableOperationalAttribute,
                    SchemaRule::EquivalentValues,
                    SchemaRule::StructuralClassChange,
                    SchemaRule::RequiredAttributes,
                    SchemaRule::AllowedAttributes,
                ],
                self::rulesOf($e),
            );
            self::assertSame(
                ResultCode::INVALID_ATTRIBUTE_SYNTAX,
                $e->getCode(),
            );
        }
    }

    public function test_a_rename_reports_every_rule_it_breaks_in_check_order(): void
    {
        $result = new Entry(
            new Dn('c=USA+jpegPhoto=zz+createTimestamp=20200101000000Z,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('c', 'USA'),
            new Attribute('jpegPhoto', 'zz'),
            new Attribute('createTimestamp', '20200101000000Z'),
            new Attribute('description', 'same', 'SAME'),
        );

        try {
            $this->subject->validate(SchemaWrite::modifyDn($result));
            self::fail('The rename breaks seven rules and should be refused.');
        } catch (SchemaValidationException $e) {
            self::assertSame(
                [
                    SchemaRule::AttributeSyntax,
                    SchemaRule::AttributeSyntax,
                    SchemaRule::NoUserModification,
                    SchemaRule::EquivalentValues,
                    SchemaRule::NamingAttributes,
                    SchemaRule::RequiredAttributes,
                    SchemaRule::AllowedAttributes,
                ],
                self::rulesOf($e),
            );
            self::assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }
    }

    public function test_a_modify_adding_an_undefined_object_class_breaks_only_that_rule(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person', '1.2.3.4.5.6.7.8'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
        );

        self::assertSame(
            [SchemaRule::DefinedObjectClasses],
            $this->rulesBrokenBy(fn() => $this->subject->validate(SchemaWrite::modify(
                $entry,
                [Change::add('objectClass', '1.2.3.4.5.6.7.8')],
            ))),
        );
    }

    public function test_valid_modify_passes(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->validate(SchemaWrite::modify(
            $this->personEntry(),
            [Change::replace(new Attribute('sn', 'Jones'))],
        ));
    }

    public function test_off_mode_does_not_throw_on_violations(): void
    {
        $subject = $this->validatorFor(TestServerOptions::validatedCore(SchemaValidationMode::Off));
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top'),
        );

        $this->expectNotToPerformAssertions();
        $subject->validate(SchemaWrite::add($entry));
    }

    public function test_system_add_skips_no_user_modification_but_keeps_structure_checks(): void
    {
        $entry = $this->personEntry();
        $entry->add(new Attribute('createTimestamp', '20240101000000Z'));

        $this->expectNotToPerformAssertions();

        $this->subject->validate(SchemaWrite::add(
            $entry,
            isSystem: true,
        ));
    }

    public function test_system_add_still_enforces_structural_class(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->subject->validate(SchemaWrite::add(
            $entry,
            isSystem: true,
        ));
    }

    public function test_system_modify_still_enforces_single_valued_attribute(): void
    {
        $result = $this->personEntry();
        $result->add(new Attribute('createTimestamp', '20240101000000Z', '20240202000000Z'));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->subject->validate(SchemaWrite::modify(
            $result,
            [Change::replace(new Attribute('createTimestamp', '20240101000000Z', '20240202000000Z'))],
            isSystem: true,
        ));
    }

    public function test_system_add_still_validates_value_syntax(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', ''),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->subject->validate(SchemaWrite::add(
            $entry,
            isSystem: true,
        ));
    }

    public function test_a_system_write_is_still_bounded(): void
    {
        $options = TestServerOptions::validatedCore(SchemaValidationMode::Strict);
        $options->getSchemaConfig()->setMaxAttributeValues(3);
        $entry = $this->personEntry();
        $entry->add(new Attribute('description', 'one', 'two', 'three', 'four'));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->validatorFor($options)->validate(SchemaWrite::add(
            $entry,
            isSystem: true,
        ));
    }

    public function test_extensible_object_still_validates_value_syntax(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person', 'extensibleObject'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('seeAlso', 'not a dn'),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->subject->validate(SchemaWrite::add($entry));
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

        $this->subject->validate(SchemaWrite::add($entry));
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

        $this->subject->validate(SchemaWrite::add($entry));
    }

    public function test_validate_values_reports_a_value_failing_its_syntax(): void
    {
        try {
            $this->subject->validateValues(new Attribute('seeAlso', 'cn=Bob,dc=example,dc=com', 'not a dn'));
            self::fail('The value is not a DN and should be refused.');
        } catch (SchemaValidationException $e) {
            self::assertEquals(
                [
                    new RuleViolation(
                        SchemaRule::AttributeSyntax,
                        ResultCode::INVALID_ATTRIBUTE_SYNTAX,
                        'A value for attribute "seeAlso" does not conform to its syntax.',
                    ),
                ],
                $e->violations,
            );
        }
    }

    public function test_validate_values_passes_conforming_values(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->validateValues(new Attribute('seeAlso', 'cn=Bob,dc=example,dc=com'));
    }

    public function test_validate_values_is_skipped_when_validation_is_off(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validatorFor(TestServerOptions::validatedCore(SchemaValidationMode::Off))
            ->validateValues(new Attribute('seeAlso', 'not a dn'));
    }

    private function validatorFor(ServerOptions $options): SchemaValidator
    {
        return $this->fromContainer(
            SchemaValidator::class,
            options: $options,
        );
    }

    /**
     * @param Closure(): void $validation
     * @return list<SchemaRule>
     */
    private function rulesBrokenBy(Closure $validation): array
    {
        try {
            $validation();
        } catch (SchemaValidationException $e) {
            return self::rulesOf($e);
        }

        return [];
    }

    /**
     * @return list<SchemaRule>
     */
    private static function rulesOf(SchemaValidationException $exception): array
    {
        return array_map(
            static fn(RuleViolation $violation): SchemaRule => $violation->rule,
            $exception->violations,
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
}
