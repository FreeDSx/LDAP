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
use FreeDSx\Ldap\Schema\Definition\MatchingRule;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\Matching\IndexableComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\Check\EquivalentValuesCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Rule\InvocationOrder;
use PHPUnit\Framework\TestCase;

final class EquivalentValuesCheckTest extends TestCase
{
    private Schema $schema;

    private EquivalentValuesCheck $subject;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->subject = new EquivalentValuesCheck(new EqualityComparatorResolver($this->schema));
    }

    public function test_add_rejects_values_equivalent_under_the_equality_rule(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'SAME', 'same'),
        );

        self::assertEquals(
            [self::violationFor('sn')],
            $this->check(SchemaWrite::add($entry)),
        );
    }

    /**
     * The values differ only by case, which caseExactMatch keeps distinct.
     */
    public function test_add_keeps_values_a_case_exact_rule_treats_as_distinct(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'inetOrgPerson'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('labeledURI', 'https://Example.test', 'https://example.test'),
        );

        self::assertSame(
            [],
            $this->check(SchemaWrite::add($entry)),
        );
    }

    public function test_add_asks_no_equality_of_values_that_cannot_match(): void
    {
        $values = [];
        foreach (range(1, 200) as $i) {
            $values[] = "value {$i}";
        }

        $this->checkWidget(
            self::never(),
            SchemaWrite::add($this->widgetEntry(new Attribute('widgetLabel', ...$values))),
        );
    }

    public function test_add_asks_equality_only_of_values_sharing_an_index_key(): void
    {
        $values = [];
        foreach (range(1, 199) as $i) {
            $values[] = "value {$i}";
        }
        $values[] = 'VALUE 199';

        self::assertEquals(
            [self::violationFor('widgetLabel')],
            $this->checkWidget(
                self::once(),
                SchemaWrite::add($this->widgetEntry(new Attribute('widgetLabel', ...$values))),
            ),
        );
    }

    public function test_modify_rejects_a_duplicate_the_change_introduces(): void
    {
        $write = SchemaWrite::modify(
            $this->widgetEntry(new Attribute('widgetLabel', 'same', 'SAME')),
            [Change::add(new Attribute('widgetLabel', 'SAME'))],
        );

        self::assertEquals(
            [self::violationFor('widgetLabel')],
            $this->checkWidget(
                self::once(),
                $write,
            ),
        );
    }

    public function test_modify_leaves_an_attribute_the_change_does_not_touch_unchecked(): void
    {
        $write = SchemaWrite::modify(
            $this->widgetEntry(
                new Attribute('widgetNote', 'after'),
                new Attribute('widgetLabel', 'same', 'SAME'),
            ),
            [Change::replace(new Attribute('widgetNote', 'after'))],
        );

        self::assertSame(
            [],
            $this->checkWidget(
                self::never(),
                $write,
            ),
        );
    }

    public function test_modify_leaves_an_attribute_with_a_linked_count_unchecked(): void
    {
        $write = SchemaWrite::modify(
            $this->widgetEntry(new Attribute(
                'widgetLabel',
                'same',
                'SAME',
            )),
            [
                Change::add(new Attribute(
                    'widgetLabel',
                    'other',
                )),
            ],
            false,
            ['widgetlabel' => 2],
        );

        self::assertSame(
            [],
            $this->checkWidget(
                self::never(),
                $write,
            ),
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

    /**
     * Checked against widget attributes whose rule bounds how many equality questions the check may ask.
     *
     * @return list<RuleViolation>
     */
    private function checkWidget(
        InvocationOrder $equalityCalls,
        SchemaWrite $write,
    ): array {
        $schema = $this->widgetSchema($equalityCalls);

        return (new EquivalentValuesCheck(new EqualityComparatorResolver($schema)))->check(
            $write,
            ObjectClassChain::forEntry(
                $schema,
                $write->entry,
            ),
        );
    }

    private function widgetEntry(Attribute ...$attributes): Entry
    {
        return new Entry(
            new Dn('cn=counted,dc=example,dc=com'),
            new Attribute('objectClass', 'widget'),
            ...$attributes,
        );
    }

    private function widgetSchema(InvocationOrder $equalityCalls): Schema
    {
        return (new Schema())
            ->addMatchingRule(new MatchingRule(
                '1.900',
                ['widgetMatch'],
                SyntaxOid::OID_DIRECTORY_STRING,
                $this->comparatorExpecting($equalityCalls),
            ))
            ->addAttributeType(new AttributeType(
                '1.5',
                ['objectClass'],
                syntaxOid: SyntaxOid::OID_OID,
            ))
            ->addAttributeType(new AttributeType(
                '1.20',
                ['widgetLabel'],
                equalityOid: '1.900',
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
            ))
            ->addAttributeType(new AttributeType(
                '1.21',
                ['widgetNote'],
                equalityOid: '1.900',
                syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
            ))
            ->addObjectClass(new ObjectClass(
                '2.20',
                ['widget'],
                ObjectClassType::StructuralClass,
                must: ['objectClass'],
                may: ['widgetLabel', 'widgetNote'],
            ));
    }

    /**
     * A caseIgnore rule expecting a given number of equality questions from the check.
     */
    private function comparatorExpecting(
        InvocationOrder $equalityCalls,
    ): MatchingRuleComparatorInterface&IndexableComparatorInterface {
        $inner = new CaseIgnoreComparator();

        /** @var MatchingRuleComparatorInterface&IndexableComparatorInterface&MockObject $comparator */
        $comparator = $this->createMockForIntersectionOfInterfaces([
            MatchingRuleComparatorInterface::class,
            IndexableComparatorInterface::class,
        ]);
        $comparator->expects($equalityCalls)
            ->method('equals')
            ->willReturnCallback($inner->equals(...));
        $comparator->method('indexKey')
            ->willReturnCallback($inner->indexKey(...));

        return $comparator;
    }

    private static function violationFor(string $attribute): RuleViolation
    {
        return new RuleViolation(
            SchemaRule::EquivalentValues,
            ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
            sprintf(
                'Attribute "%s" is supplied an equivalent value more than once.',
                $attribute,
            ),
        );
    }
}
