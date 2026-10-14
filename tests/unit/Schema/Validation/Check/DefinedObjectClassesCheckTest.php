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
use FreeDSx\Ldap\Schema\Validation\Check\DefinedObjectClassesCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use PHPUnit\Framework\TestCase;

final class DefinedObjectClassesCheckTest extends TestCase
{
    private Schema $schema;

    private DefinedObjectClassesCheck $subject;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->subject = new DefinedObjectClassesCheck($this->schema);
    }

    public function test_add_undefined_object_class_reports_an_object_class_violation(): void
    {
        self::assertEquals(
            [
                new RuleViolation(
                    SchemaRule::DefinedObjectClasses,
                    ResultCode::OBJECT_CLASS_VIOLATION,
                    'Undefined object class: "xNoSuchClass".',
                ),
            ],
            $this->check($this->personOf('top', 'person', 'xNoSuchClass')),
        );
    }

    public function test_an_entry_of_defined_classes_passes(): void
    {
        self::assertSame(
            [],
            $this->check($this->personOf('top', 'person')),
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

    private function personOf(string ...$objectClasses): Entry
    {
        return new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', ...$objectClasses),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
        );
    }
}
