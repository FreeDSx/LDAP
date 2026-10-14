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
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\Check\NoUserModificationCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class NoUserModificationCheckTest extends TestCase
{
    private const SET_BY_USERS = 'Attribute "%s" cannot be set by users.';

    private const MODIFIED_BY_USERS = 'Attribute "%s" cannot be modified by users.';

    private Schema $schema;

    private NoUserModificationCheck $subject;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->subject = new NoUserModificationCheck($this->schema);
    }

    #[DataProvider('noUserModificationAddProvider')]
    public function test_an_add_reports_a_no_user_modification_attribute_under_the_rule_that_governs_it(
        string $attribute,
        string $value,
        SchemaRule $expected,
    ): void {
        $entry = $this->personEntry();
        $entry->add(new Attribute(
            $attribute,
            $value,
        ));

        self::assertEquals(
            [
                self::violation(
                    $expected,
                    self::SET_BY_USERS,
                    $attribute,
                ),
            ],
            $this->check(SchemaWrite::add($entry)),
        );
    }

    /**
     * @return Generator<string, array{attribute: string, value: string, expected: SchemaRule}>
     */
    public static function noUserModificationAddProvider(): Generator
    {
        yield 'entryUUID may be supplied on add' => [
            'attribute' => 'entryUUID',
            'value' => '597ae2f6-16a6-1027-98f4-d28b5365dc14',
            'expected' => SchemaRule::SettableOperationalAttribute,
        ];

        yield 'creatorsName may be supplied on add' => [
            'attribute' => 'creatorsName',
            'value' => 'cn=Jane,dc=example,dc=com',
            'expected' => SchemaRule::SettableOperationalAttribute,
        ];

        yield 'structuralObjectClass may not' => [
            'attribute' => 'structuralObjectClass',
            'value' => 'device',
            'expected' => SchemaRule::NoUserModification,
        ];
    }

    public function test_an_add_reports_an_unsettable_attribute_beside_a_settable_one(): void
    {
        $entry = $this->personEntry();
        $entry->add(new Attribute('createTimestamp', '20200101000000Z'));
        $entry->add(new Attribute('structuralObjectClass', 'device'));

        self::assertEquals(
            [
                self::violation(
                    SchemaRule::NoUserModification,
                    self::SET_BY_USERS,
                    'structuralObjectClass',
                ),
                self::violation(
                    SchemaRule::SettableOperationalAttribute,
                    self::SET_BY_USERS,
                    'createTimestamp',
                ),
            ],
            $this->check(SchemaWrite::add($entry)),
        );
    }

    public function test_a_modify_may_supply_a_timestamp_but_not_the_entry_uuid(): void
    {
        $write = SchemaWrite::modify(
            $this->personEntry(),
            [
                Change::replace('modifyTimestamp', '20200101000000Z'),
                Change::replace('entryUUID', '597ae2f6-16a6-1027-98f4-d28b5365dc14'),
            ],
        );

        self::assertEquals(
            [
                self::violation(
                    SchemaRule::NoUserModification,
                    self::MODIFIED_BY_USERS,
                    'entryUUID',
                ),
                self::violation(
                    SchemaRule::SettableOperationalAttribute,
                    self::MODIFIED_BY_USERS,
                    'modifyTimestamp',
                ),
            ],
            $this->check($write),
        );
    }

    public function test_add_no_user_modification_attribute_reports_a_constraint_violation(): void
    {
        $entry = $this->personEntry();
        $entry->add(new Attribute('createTimestamp', '20240101000000Z'));

        self::assertEquals(
            [
                self::violation(
                    SchemaRule::SettableOperationalAttribute,
                    self::SET_BY_USERS,
                    'createTimestamp',
                ),
            ],
            $this->check(SchemaWrite::add($entry)),
        );
    }

    public function test_modify_no_user_modification_attribute_reports_a_constraint_violation(): void
    {
        $write = SchemaWrite::modify(
            $this->personEntry(),
            [Change::replace(new Attribute('createTimestamp', '20240101000000Z'))],
        );

        self::assertEquals(
            [
                self::violation(
                    SchemaRule::SettableOperationalAttribute,
                    self::MODIFIED_BY_USERS,
                    'createTimestamp',
                ),
            ],
            $this->check($write),
        );
    }

    public function test_system_modify_skips_no_user_modification_check(): void
    {
        $write = SchemaWrite::modify(
            $this->personEntry(),
            [Change::replace(new Attribute('createTimestamp', '20240101000000Z'))],
            isSystem: true,
        );

        self::assertSame(
            [],
            $this->check($write),
        );
    }

    public function test_a_rename_reports_a_no_user_modification_attribute_named_by_its_new_rdn(): void
    {
        $entry = $this->personEntry('createTimestamp=20200101000000Z,dc=example,dc=com');
        $entry->add(new Attribute('createTimestamp', '20200101000000Z'));

        self::assertEquals(
            [
                self::violation(
                    SchemaRule::NoUserModification,
                    self::SET_BY_USERS,
                    'createTimestamp',
                ),
            ],
            $this->check(SchemaWrite::modifyDn($entry)),
        );
    }

    public function test_a_rename_leaves_attributes_outside_its_new_rdn_unchecked(): void
    {
        $entry = $this->personEntry();
        $entry->add(new Attribute('createTimestamp', '20200101000000Z'));

        self::assertSame(
            [],
            $this->check(SchemaWrite::modifyDn($entry)),
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

    private function personEntry(string $dn = 'cn=Alice,dc=example,dc=com'): Entry
    {
        return new Entry(
            new Dn($dn),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
        );
    }

    private static function violation(
        SchemaRule $rule,
        string $message,
        string $attribute,
    ): RuleViolation {
        return new RuleViolation(
            $rule,
            ResultCode::CONSTRAINT_VIOLATION,
            sprintf(
                $message,
                $attribute,
            ),
        );
    }
}
