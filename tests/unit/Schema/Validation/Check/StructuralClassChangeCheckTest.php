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
use FreeDSx\Ldap\Schema\Validation\Check\StructuralClassChangeCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use PHPUnit\Framework\TestCase;

final class StructuralClassChangeCheckTest extends TestCase
{
    private Schema $schema;

    private StructuralClassChangeCheck $subject;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->subject = new StructuralClassChangeCheck();
    }

    public function test_modify_rejects_changing_the_structural_object_class(): void
    {
        $write = SchemaWrite::modify(
            $this->groupChangedToUniqueNames(),
            [Change::replace(new Attribute('objectClass', 'groupOfUniqueNames'))],
        );

        self::assertEquals(
            [
                new RuleViolation(
                    SchemaRule::StructuralClassChange,
                    ResultCode::OBJECT_CLASS_MODS_PROHIBITED,
                    'The structural object class cannot be changed from "groupOfNames" to "groupOfUniqueNames".',
                ),
            ],
            $this->check($write),
        );
    }

    public function test_modify_keeps_an_unchanged_structural_object_class(): void
    {
        $write = SchemaWrite::modify(
            new Entry(
                new Dn('cn=group,dc=example,dc=com'),
                new Attribute('objectClass', 'groupOfNames'),
                new Attribute('cn', 'group'),
                new Attribute('member', 'cn=someone,dc=example,dc=com'),
                new Attribute('description', 'A group'),
                new Attribute('structuralObjectClass', 'groupOfNames'),
            ),
            [Change::add(new Attribute('description', 'A group'))],
        );

        self::assertSame(
            [],
            $this->check($write),
        );
    }

    public function test_an_add_is_not_checked(): void
    {
        self::assertSame(
            [],
            $this->check(SchemaWrite::add($this->groupChangedToUniqueNames())),
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

    private function groupChangedToUniqueNames(): Entry
    {
        return new Entry(
            new Dn('cn=group,dc=example,dc=com'),
            new Attribute('objectClass', 'groupOfUniqueNames'),
            new Attribute('cn', 'group'),
            new Attribute('uniqueMember', 'cn=someone,dc=example,dc=com'),
            new Attribute('structuralObjectClass', 'groupOfNames'),
        );
    }
}
