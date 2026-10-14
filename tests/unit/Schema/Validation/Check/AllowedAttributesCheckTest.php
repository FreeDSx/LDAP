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
use FreeDSx\Ldap\Schema\Validation\Check\AllowedAttributesCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use PHPUnit\Framework\TestCase;

final class AllowedAttributesCheckTest extends TestCase
{
    private Schema $schema;

    private AllowedAttributesCheck $subject;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->subject = new AllowedAttributesCheck($this->schema);
    }

    public function test_add_disallowed_attribute_reports_an_object_class_violation(): void
    {
        self::assertEquals(
            [
                new RuleViolation(
                    SchemaRule::AllowedAttributes,
                    ResultCode::OBJECT_CLASS_VIOLATION,
                    'Attribute "employeeNumber" is not permitted by any object class.',
                ),
            ],
            $this->check($this->personOf(
                ['top', 'person'],
                new Attribute('employeeNumber', '42'),
            )),
        );
    }

    public function test_add_extensible_object_waives_the_permitted_attribute_list(): void
    {
        // Defined by the schema but permitted by neither person nor extensibleObject's own MAY list.
        self::assertSame(
            [],
            $this->check($this->personOf(
                ['person', 'extensibleObject'],
                new Attribute('l', 'Somewhere'),
            )),
        );
    }

    public function test_an_operational_attribute_needs_no_object_class_to_permit_it(): void
    {
        self::assertSame(
            [],
            $this->check($this->personOf(
                ['top', 'person'],
                new Attribute('createTimestamp', '20240101000000Z'),
            )),
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

    /**
     * @param list<string> $objectClasses
     */
    private function personOf(
        array $objectClasses,
        Attribute ...$attributes,
    ): Entry {
        return new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', ...$objectClasses),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            ...$attributes,
        );
    }
}
