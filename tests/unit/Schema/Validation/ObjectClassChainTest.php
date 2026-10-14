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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Validation;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use PHPUnit\Framework\TestCase;

final class ObjectClassChainTest extends TestCase
{
    private Schema $schema;

    protected function setUp(): void
    {
        $this->schema = (new Schema())
            ->addAttributeType(new AttributeType('1.1', ['cn']))
            ->addAttributeType(new AttributeType('1.2', ['sn']))
            ->addAttributeType(new AttributeType('1.3', ['description']))
            ->addAttributeType(new AttributeType('1.4', ['ou']))
            ->addAttributeType(new AttributeType('1.5', ['objectClass']));
    }

    public function test_empty_input_yields_empty_must_and_may(): void
    {
        $chain = new ObjectClassChain(
            $this->schema,
            [],
        );

        self::assertSame(
            [],
            $chain->must,
        );
        self::assertSame(
            [],
            $chain->may,
        );
    }

    public function test_single_class_must_and_may_are_collected(): void
    {
        $oc = new ObjectClass(
            '2.1',
            ['person'],
            must: ['cn'],
            may: ['description'],
        );
        $chain = new ObjectClassChain(
            $this->schema,
            [$oc],
        );

        self::assertSame(
            ['cn'],
            $chain->must,
        );
        self::assertSame(
            ['description'],
            $chain->may,
        );
    }

    public function test_attributes_are_lowercased(): void
    {
        $oc = new ObjectClass(
            '2.1',
            ['Person'],
            must: ['CN'],
            may: ['Description'],
        );
        $chain = new ObjectClassChain(
            $this->schema,
            [$oc],
        );

        self::assertSame(
            ['cn'],
            $chain->must,
        );
        self::assertSame(
            ['description'],
            $chain->may,
        );
    }

    public function test_canonical_name_is_used_when_attribute_is_known(): void
    {
        $schema = (new Schema())
            ->addAttributeType(new AttributeType('1.1', ['commonName', 'cn']));

        $oc = new ObjectClass(
            '2.1',
            ['person'],
            must: ['cn'],
        );
        $chain = new ObjectClassChain(
            $schema,
            [$oc],
        );

        self::assertSame(
            ['commonname'],
            $chain->must,
        );
    }

    public function test_superclass_must_and_may_are_inherited(): void
    {
        $parent = new ObjectClass(
            '2.0',
            ['top'],
            must: ['objectClass'],
        );
        $child = new ObjectClass(
            '2.1',
            ['person'],
            superClassOids: ['2.0'],
            must: ['cn'],
            may: ['description'],
        );

        $schema = (new Schema())
            ->addObjectClass($parent)
            ->addAttributeType(new AttributeType('1.1', ['cn']))
            ->addAttributeType(new AttributeType('1.5', ['objectClass']))
            ->addAttributeType(new AttributeType('1.3', ['description']));

        $chain = new ObjectClassChain(
            $schema,
            [$child],
        );

        self::assertContains(
            'cn',
            $chain->must,
        );
        self::assertContains(
            'objectclass',
            $chain->must,
        );
        self::assertContains(
            'description',
            $chain->may,
        );
    }

    public function test_duplicate_attributes_across_classes_are_deduplicated(): void
    {
        $oc1 = new ObjectClass(
            '2.1',
            ['person'],
            must: ['cn', 'sn'],
        );
        $oc2 = new ObjectClass(
            '2.2',
            ['orgPerson'],
            must: ['cn', 'ou'],
        );

        $chain = new ObjectClassChain(
            $this->schema,
            [$oc1, $oc2],
        );

        self::assertSame(
            ['cn', 'sn', 'ou'],
            $chain->must,
        );
    }

    public function test_diamond_inheritance_visits_each_class_once(): void
    {
        $root = new ObjectClass(
            '2.0',
            ['top'],
            must: ['objectClass'],
        );
        $left = new ObjectClass(
            '2.1',
            ['left'],
            superClassOids: ['2.0'],
            must: ['cn'],
        );
        $right = new ObjectClass(
            '2.2',
            ['right'],
            superClassOids: ['2.0'],
            must: ['sn'],
        );
        $child = new ObjectClass(
            '2.3',
            ['child'],
            superClassOids: ['2.1', '2.2'],
            must: ['ou'],
        );

        $schema = (new Schema())
            ->addObjectClass($root)
            ->addObjectClass($left)
            ->addObjectClass($right)
            ->addAttributeType(new AttributeType('1.1', ['cn']))
            ->addAttributeType(new AttributeType('1.2', ['sn']))
            ->addAttributeType(new AttributeType('1.4', ['ou']))
            ->addAttributeType(new AttributeType('1.5', ['objectClass']));

        $chain = new ObjectClassChain(
            $schema,
            [$child],
        );

        self::assertCount(
            1,
            array_filter($chain->must, fn(string $a) => $a === 'objectclass'),
        );
    }

    public function test_unknown_superclass_oid_is_skipped_gracefully(): void
    {
        $oc = new ObjectClass(
            '2.1',
            ['person'],
            superClassOids: ['99.99.99'],
            must: ['cn'],
        );
        $chain = new ObjectClassChain(
            $this->schema,
            [$oc],
        );

        self::assertSame(
            ['cn'],
            $chain->must,
        );
    }

    public function test_unknown_attribute_name_falls_back_to_original_lowercased(): void
    {
        $oc = new ObjectClass(
            '2.1',
            ['custom'],
            must: ['unknownAttr'],
        );
        $chain = new ObjectClassChain(
            $this->schema,
            [$oc],
        );

        self::assertSame(
            ['unknownattr'],
            $chain->must,
        );
    }

    public function test_auxiliary_class_attributes_are_included(): void
    {
        $aux = new ObjectClass(
            '2.5',
            ['posixAccount'],
            ObjectClassType::AuxiliaryClass,
            must: ['ou'],
        );
        $structural = new ObjectClass(
            '2.1',
            ['person'],
            must: ['cn', 'sn'],
        );

        $chain = new ObjectClassChain(
            $this->schema,
            [$structural, $aux],
        );

        self::assertContains(
            'cn',
            $chain->must,
        );
        self::assertContains(
            'ou',
            $chain->must,
        );
    }

    public function test_for_entry_resolves_only_the_classes_the_schema_defines(): void
    {
        $person = new ObjectClass(
            '2.1',
            ['person'],
            must: ['cn'],
        );
        $this->schema->addObjectClass($person);

        $chain = ObjectClassChain::forEntry(
            $this->schema,
            new Entry(
                new Dn('cn=Alice,dc=example,dc=com'),
                new Attribute('objectClass', 'person', 'xNoSuchClass'),
            ),
        );

        self::assertSame(
            [$person],
            $chain->classes,
        );
    }

    public function test_the_structural_head_is_the_most_subordinate_structural_class(): void
    {
        $alpha = new ObjectClass(
            '2.1',
            ['alpha'],
        );
        $alphaChild = new ObjectClass(
            '2.2',
            ['alphaChild'],
            superClassOids: ['2.1'],
        );
        $this->schema
            ->addObjectClass($alpha)
            ->addObjectClass($alphaChild);

        $chain = new ObjectClassChain(
            $this->schema,
            [$alpha, $alphaChild],
        );

        self::assertSame(
            $alphaChild,
            $chain->structuralHead,
        );
    }

    public function test_unrelated_structural_classes_have_no_head(): void
    {
        $alpha = new ObjectClass(
            '2.1',
            ['alpha'],
        );
        $beta = new ObjectClass(
            '2.2',
            ['beta'],
        );

        $chain = new ObjectClassChain(
            $this->schema,
            [$alpha, $beta],
        );

        self::assertSame(
            [$alpha, $beta],
            $chain->structural,
        );
        self::assertNull($chain->structuralHead);
    }

    public function test_auxiliary_classes_are_not_structural(): void
    {
        $structural = new ObjectClass(
            '2.1',
            ['person'],
        );
        $aux = new ObjectClass(
            '2.5',
            ['posixAccount'],
            ObjectClassType::AuxiliaryClass,
        );

        $chain = new ObjectClassChain(
            $this->schema,
            [$structural, $aux],
        );

        self::assertSame(
            [$structural],
            $chain->structural,
        );
        self::assertSame(
            $structural,
            $chain->structuralHead,
        );
    }
}
