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
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\Check\ValueLimitCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use PHPUnit\Framework\TestCase;

final class ValueLimitCheckTest extends TestCase
{
    private Schema $schema;

    private ValueLimitCheck $subject;

    protected function setUp(): void
    {
        $this->schema = (new Schema())
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
        $this->subject = new ValueLimitCheck(
            $this->schema,
            new LinkedAttributes($this->schema),
            3,
        );
    }

    public function test_add_beyond_the_default_value_limit_is_refused(): void
    {
        self::assertEquals(
            [self::violation('Attribute "gadgetPlain" holds 4 values, which is beyond the limit of 3.')],
            $this->check(SchemaWrite::add($this->gadgetEntry(new Attribute('gadgetPlain', ...self::values(4))))),
        );
    }

    public function test_add_at_the_default_value_limit_passes(): void
    {
        self::assertSame(
            [],
            $this->check(SchemaWrite::add($this->gadgetEntry(new Attribute('gadgetPlain', ...self::values(3))))),
        );
    }

    public function test_a_type_declaring_a_stricter_cap_is_refused_below_the_default(): void
    {
        self::assertEquals(
            [self::violation('Attribute "gadgetStricter" holds 2 values, which is beyond the limit of 1.')],
            $this->check(SchemaWrite::add($this->gadgetEntry(new Attribute('gadgetStricter', ...self::values(2))))),
        );
    }

    public function test_a_type_declaring_a_looser_cap_passes_above_the_default(): void
    {
        self::assertSame(
            [],
            $this->check(SchemaWrite::add($this->gadgetEntry(new Attribute('gadgetLooser', ...self::values(6))))),
        );
    }

    public function test_a_type_declaring_a_looser_cap_is_still_refused_beyond_it(): void
    {
        self::assertEquals(
            [self::violation('Attribute "gadgetLooser" holds 7 values, which is beyond the limit of 6.')],
            $this->check(SchemaWrite::add($this->gadgetEntry(new Attribute('gadgetLooser', ...self::values(7))))),
        );
    }

    public function test_a_type_declaring_a_zero_cap_is_unbounded(): void
    {
        self::assertSame(
            [],
            $this->check(SchemaWrite::add($this->gadgetEntry(new Attribute('gadgetUnbounded', ...self::values(50))))),
        );
    }

    public function test_an_option_bearing_form_is_held_to_the_cap_of_the_type_it_subtypes(): void
    {
        self::assertEquals(
            [self::violation('Attribute "gadgetStricter" holds 2 values, which is beyond the limit of 1.')],
            $this->check(SchemaWrite::add(
                $this->gadgetEntry(new Attribute('gadgetStricter;lang-en', ...self::values(2))),
            )),
        );
    }

    public function test_a_linked_attribute_is_not_bounded(): void
    {
        $schema = SchemaResource::Core->load();
        $subject = new ValueLimitCheck(
            $schema,
            new LinkedAttributes($schema),
            3,
        );
        $entry = new Entry(
            new Dn('cn=Team,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'groupOfNames'),
            new Attribute('cn', 'Team'),
            new Attribute('member', ...array_map(
                static fn(int $i): string => "cn=user$i,dc=example,dc=com",
                range(1, 50),
            )),
        );

        self::assertSame(
            [],
            $subject->check(
                SchemaWrite::add($entry),
                ObjectClassChain::forEntry(
                    $schema,
                    $entry,
                ),
            ),
        );
    }

    public function test_a_modify_crossing_the_value_limit_is_refused(): void
    {
        $write = SchemaWrite::modify(
            $this->gadgetEntry(new Attribute('gadgetPlain', ...self::values(4))),
            [Change::add(new Attribute('gadgetPlain', 'value 4'))],
        );

        self::assertEquals(
            [self::violation('Attribute "gadgetPlain" holds 4 values, which is beyond the limit of 3.')],
            $this->check($write),
        );
    }

    public function test_a_modify_staying_within_the_value_limit_passes(): void
    {
        $write = SchemaWrite::modify(
            $this->gadgetEntry(new Attribute('gadgetPlain', ...self::values(3))),
            [Change::add(new Attribute('gadgetPlain', 'value 3'))],
        );

        self::assertSame(
            [],
            $this->check($write),
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

    private static function violation(string $message): RuleViolation
    {
        return new RuleViolation(
            SchemaRule::ValueLimit,
            ResultCode::ADMIN_LIMIT_EXCEEDED,
            $message,
        );
    }
}
