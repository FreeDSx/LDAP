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
use FreeDSx\Ldap\Schema\Validation\Check\SingleValueCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use PHPUnit\Framework\TestCase;

final class SingleValueCheckTest extends TestCase
{
    private Schema $schema;

    private SingleValueCheck $subject;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->subject = new SingleValueCheck($this->schema);
    }

    public function test_add_single_valued_violation_reports_a_constraint_violation(): void
    {
        self::assertEquals(
            [
                new RuleViolation(
                    SchemaRule::SingleValue,
                    ResultCode::CONSTRAINT_VIOLATION,
                    'Attribute "employeeNumber" is single-valued but has 2 values.',
                ),
            ],
            $this->check($this->inetOrgPersonWith(new Attribute('employeeNumber', '001', '002'))),
        );
    }

    public function test_a_single_valued_attribute_holding_one_value_passes(): void
    {
        self::assertSame(
            [],
            $this->check($this->inetOrgPersonWith(new Attribute('employeeNumber', '001'))),
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

    private function inetOrgPersonWith(Attribute $attribute): Entry
    {
        return new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person', 'organizationalPerson', 'inetOrgPerson'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            $attribute,
        );
    }
}
