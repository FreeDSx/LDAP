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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Validation\Check;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\Check\AttributeSyntaxCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use PHPUnit\Framework\TestCase;

final class AttributeSyntaxCheckTest extends TestCase
{
    private Schema $schema;

    private AttributeSyntaxCheck $subject;

    protected function setUp(): void
    {
        $this->schema = (new Schema())
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
            ->addAttributeType(new AttributeType(
                '1.14',
                ['widgetName'],
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
            ))
            ->addObjectClass(new ObjectClass(
                '2.10',
                ['widget'],
                ObjectClassType::StructuralClass,
                must: ['objectClass'],
                may: ['widgetCount', 'widgetOwner', 'widgetSeenAt', 'widgetActive', 'widgetName'],
            ));
        $this->subject = new AttributeSyntaxCheck(new AttributeSyntaxResolver($this->schema));
    }

    public function test_add_invalid_integer_value_reports_invalid_attribute_syntax(): void
    {
        self::assertEquals(
            [self::violationFor('widgetCount')],
            $this->check(SchemaWrite::add($this->widgetEntry(new Attribute('widgetCount', 'not-a-number')))),
        );
    }

    public function test_add_invalid_distinguished_name_value_reports_invalid_attribute_syntax(): void
    {
        self::assertEquals(
            [self::violationFor('widgetOwner')],
            $this->check(SchemaWrite::add($this->widgetEntry(new Attribute('widgetOwner', 'not a dn')))),
        );
    }

    public function test_add_empty_directory_string_value_reports_invalid_attribute_syntax(): void
    {
        self::assertEquals(
            [self::violationFor('widgetName')],
            $this->check(SchemaWrite::add($this->widgetEntry(new Attribute('widgetName', '')))),
        );
    }

    public function test_add_with_conforming_values_passes(): void
    {
        $entry = $this->widgetEntry(
            new Attribute('widgetCount', '42'),
            new Attribute('widgetOwner', 'cn=Owner,dc=example,dc=com'),
            new Attribute('widgetSeenAt', '20240101000000Z'),
            new Attribute('widgetActive', 'TRUE'),
            new Attribute('widgetName', 'Sprocket'),
        );

        self::assertSame(
            [],
            $this->check(SchemaWrite::add($entry)),
        );
    }

    public function test_modify_invalid_generalized_time_reports_invalid_attribute_syntax(): void
    {
        $result = $this->widgetEntry(new Attribute('widgetSeenAt', 'not-a-time'));

        self::assertEquals(
            [self::violationFor('widgetSeenAt')],
            $this->check(SchemaWrite::modify(
                $result,
                [Change::replace(new Attribute('widgetSeenAt', 'not-a-time'))],
            )),
        );
    }

    public function test_only_the_first_attribute_failing_its_syntax_is_reported(): void
    {
        $entry = $this->widgetEntry(
            new Attribute('widgetCount', 'not-a-number'),
            new Attribute('widgetOwner', 'not a dn'),
        );

        self::assertEquals(
            [self::violationFor('widgetCount')],
            $this->check(SchemaWrite::add($entry)),
        );
    }

    /**
     * @return list<RuleViolation>
     */
    private function check(SchemaWrite $write): array
    {
        return $this->subject->check(
            $write,
            ObjectClassChain::forEntry(
                $this->schema,
                $write->entry,
            ),
        );
    }

    private function widgetEntry(Attribute ...$attributes): Entry
    {
        return new Entry(
            new Dn('cn=Widget,dc=example,dc=com'),
            new Attribute('objectClass', 'widget'),
            ...$attributes,
        );
    }

    private static function violationFor(string $attribute): RuleViolation
    {
        return new RuleViolation(
            SchemaRule::AttributeSyntax,
            ResultCode::INVALID_ATTRIBUTE_SYNTAX,
            sprintf(
                'A value for attribute "%s" does not conform to its syntax.',
                $attribute,
            ),
        );
    }
}
