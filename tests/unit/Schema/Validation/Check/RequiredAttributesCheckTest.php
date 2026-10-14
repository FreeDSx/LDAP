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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\Check\RequiredAttributesCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use PHPUnit\Framework\TestCase;

final class RequiredAttributesCheckTest extends TestCase
{
    private Schema $schema;

    private RequiredAttributesCheck $subject;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->subject = new RequiredAttributesCheck($this->schema);
    }

    public function test_add_missing_must_attribute_reports_an_object_class_violation(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
        );

        self::assertEquals(
            [
                new RuleViolation(
                    SchemaRule::RequiredAttributes,
                    ResultCode::OBJECT_CLASS_VIOLATION,
                    'Required attribute "sn" is missing.',
                ),
            ],
            $this->check($entry),
        );
    }

    public function test_a_required_attribute_supplied_under_another_name_passes(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('surname', 'Smith'),
        );

        self::assertSame(
            [],
            $this->check($entry),
        );
    }

    /**
     * A group is allowed to hold no members, so that one can be created before its members and survive their removal.
     */
    public function test_add_accepts_a_group_holding_no_members(): void
    {
        $entry = new Entry(
            new Dn('cn=empty,dc=example,dc=com'),
            new Attribute('objectClass', 'groupOfNames'),
            new Attribute('cn', 'empty'),
        );

        self::assertSame(
            [],
            $this->check($entry),
        );
    }

    /**
     * @return list<RuleViolation>
     */
    private function check(Entry $entry): array
    {
        return $this->subject->check(
            SchemaWrite::add($entry),
            ObjectClassChain::forEntry(
                $this->schema,
                $entry,
            ),
        );
    }
}
