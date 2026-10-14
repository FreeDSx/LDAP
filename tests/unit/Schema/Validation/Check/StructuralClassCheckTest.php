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
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\Check\StructuralClassCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use PHPUnit\Framework\TestCase;

final class StructuralClassCheckTest extends TestCase
{
    private Schema $schema;

    private StructuralClassCheck $subject;

    protected function setUp(): void
    {
        $this->schema = (new Schema())
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
        $this->subject = new StructuralClassCheck();
    }

    public function test_add_missing_structural_class_reports_an_object_class_violation(): void
    {
        self::assertEquals(
            [self::violation('Entry "cn=Thing,dc=example,dc=com" must have at least one structural object class.')],
            $this->check($this->thingOf('top')),
        );
    }

    public function test_add_structural_chain_passes(): void
    {
        self::assertSame(
            [],
            $this->check($this->thingOf('top', 'alpha', 'alphaChild')),
        );
    }

    public function test_add_two_unrelated_structural_classes_reports_an_object_class_violation(): void
    {
        self::assertEquals(
            [self::violation('Entry "cn=Thing,dc=example,dc=com" must not combine unrelated structural object classes.')],
            $this->check($this->thingOf('top', 'alpha', 'beta')),
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

    private function thingOf(string ...$objectClasses): Entry
    {
        return new Entry(
            new Dn('cn=Thing,dc=example,dc=com'),
            new Attribute('objectClass', ...$objectClasses),
        );
    }

    private static function violation(string $message): RuleViolation
    {
        return new RuleViolation(
            SchemaRule::StructuralClass,
            ResultCode::OBJECT_CLASS_VIOLATION,
            $message,
        );
    }
}
