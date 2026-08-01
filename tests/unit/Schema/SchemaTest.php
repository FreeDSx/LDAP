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

namespace Tests\Unit\FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\LdapSyntax;
use FreeDSx\Ldap\Schema\Definition\MatchingRule;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Schema;
use PHPUnit\Framework\TestCase;

final class SchemaTest extends TestCase
{
    private Schema $subject;

    private AttributeType $cn;

    private ObjectClass $person;

    private MatchingRule $caseIgnore;

    private LdapSyntax $dirString;

    protected function setUp(): void
    {
        $this->subject = new Schema();

        $this->cn = new AttributeType(
            oid: '2.5.4.3',
            names: ['cn', 'commonName'],
        );
        $this->person = new ObjectClass(
            oid: '2.5.6.6',
            names: ['person'],
        );
        $this->caseIgnore = new MatchingRule(
            oid: '2.5.13.2',
            names: ['caseIgnoreMatch'],
            syntaxOid: '1.3.6.1.4.1.1466.115.121.1.15',
            comparator: new CaseIgnoreComparator(),
        );
        $this->dirString = new LdapSyntax(
            oid: '1.3.6.1.4.1.1466.115.121.1.15',
            desc: 'Directory String',
        );
    }

    public function test_add_and_get_attribute_type_by_oid(): void
    {
        $this->subject->addAttributeType($this->cn);

        self::assertSame(
            $this->cn,
            $this->subject->getAttributeType('2.5.4.3'),
        );
    }

    public function test_add_and_get_attribute_type_by_primary_name(): void
    {
        $this->subject->addAttributeType($this->cn);

        self::assertSame(
            $this->cn,
            $this->subject->getAttributeType('cn'),
        );
    }

    public function test_add_and_get_attribute_type_by_alias(): void
    {
        $this->subject->addAttributeType($this->cn);

        self::assertSame(
            $this->cn,
            $this->subject->getAttributeType('commonName'),
        );
    }

    public function test_get_attribute_type_case_insensitive(): void
    {
        $this->subject->addAttributeType($this->cn);

        self::assertSame(
            $this->cn,
            $this->subject->getAttributeType('CN'),
        );
        self::assertSame(
            $this->cn,
            $this->subject->getAttributeType('CommonName'),
        );
    }

    public function test_get_attribute_type_returns_null_when_not_found(): void
    {
        self::assertNull($this->subject->getAttributeType('sn'));
    }

    public function test_add_and_get_object_class_by_oid(): void
    {
        $this->subject->addObjectClass($this->person);

        self::assertSame(
            $this->person,
            $this->subject->getObjectClass('2.5.6.6'),
        );
    }

    public function test_add_and_get_object_class_by_name(): void
    {
        $this->subject->addObjectClass($this->person);

        self::assertSame(
            $this->person,
            $this->subject->getObjectClass('person'),
        );
    }

    public function test_get_object_class_case_insensitive(): void
    {
        $this->subject->addObjectClass($this->person);

        self::assertSame(
            $this->person,
            $this->subject->getObjectClass('Person'),
        );
    }

    public function test_get_object_class_returns_null_when_not_found(): void
    {
        self::assertNull($this->subject->getObjectClass('inetOrgPerson'));
    }

    public function test_add_and_get_matching_rule_by_oid(): void
    {
        $this->subject->addMatchingRule($this->caseIgnore);

        self::assertSame(
            $this->caseIgnore,
            $this->subject->getMatchingRule('2.5.13.2'),
        );
    }

    public function test_add_and_get_matching_rule_by_name(): void
    {
        $this->subject->addMatchingRule($this->caseIgnore);

        self::assertSame(
            $this->caseIgnore,
            $this->subject->getMatchingRule('caseIgnoreMatch'),
        );
    }

    public function test_get_matching_rule_returns_null_when_not_found(): void
    {
        self::assertNull($this->subject->getMatchingRule('caseExactMatch'));
    }

    public function test_add_and_get_syntax_by_oid(): void
    {
        $this->subject->addSyntax($this->dirString);

        self::assertSame(
            $this->dirString,
            $this->subject->getSyntax('1.3.6.1.4.1.1466.115.121.1.15'),
        );
    }

    public function test_get_syntax_returns_null_when_not_found(): void
    {
        self::assertNull($this->subject->getSyntax('1.3.6.1.4.1.1466.115.121.1.27'));
    }

    public function test_get_comparator_returns_comparator_for_registered_rule(): void
    {
        $this->subject->addMatchingRule($this->caseIgnore);

        self::assertInstanceOf(
            CaseIgnoreComparator::class,
            $this->subject->getComparator('2.5.13.2'),
        );
    }

    public function test_get_comparator_returns_null_for_unknown_rule(): void
    {
        self::assertNull($this->subject->getComparator('2.5.13.99'));
    }

    public function test_get_attribute_types_returns_unique_list(): void
    {
        $this->subject->addAttributeType($this->cn);

        $types = $this->subject->getAttributeTypes();

        self::assertCount(1, $types);
        self::assertSame(
            $this->cn,
            $types[0],
        );
    }

    public function test_get_object_classes_returns_unique_list(): void
    {
        $this->subject->addObjectClass($this->person);

        $classes = $this->subject->getObjectClasses();

        self::assertCount(1, $classes);
        self::assertSame(
            $this->person,
            $classes[0],
        );
    }

    public function test_get_matching_rules_returns_unique_list(): void
    {
        $this->subject->addMatchingRule($this->caseIgnore);

        $rules = $this->subject->getMatchingRules();

        self::assertCount(1, $rules);
        self::assertSame(
            $this->caseIgnore,
            $rules[0],
        );
    }

    public function test_merge_combines_definitions(): void
    {
        $this->subject->addAttributeType($this->cn);

        $other = (new Schema())->addObjectClass($this->person);
        $merged = $this->subject->merge($other);

        self::assertSame(
            $this->cn,
            $merged->getAttributeType('cn'),
        );
        self::assertSame(
            $this->person,
            $merged->getObjectClass('person'),
        );
    }

    public function test_merge_does_not_mutate_original(): void
    {
        $this->subject->addAttributeType($this->cn);

        $other = (new Schema())->addObjectClass($this->person);
        $this->subject->merge($other);

        self::assertNull($this->subject->getObjectClass('person'));
    }

    public function test_merge_other_overrides_on_collision(): void
    {
        $original = new AttributeType(
            oid: '2.5.4.3',
            names: ['cn'],
            desc: 'original',
        );
        $override = new AttributeType(
            oid: '2.5.4.3',
            names: ['cn'],
            desc: 'override',
        );
        $this->subject->addAttributeType($original);

        $other = (new Schema())->addAttributeType($override);
        $merged = $this->subject->merge($other);

        self::assertSame(
            'override',
            $merged->getAttributeType('cn')?->desc,
        );
    }

    public function test_merge_carries_forward_an_extension_the_incoming_definition_omits(): void
    {
        $this->subject->addAttributeType(new AttributeType(
            oid: '2.5.4.35',
            names: ['userPassword'],
            extensions: [AttributeType::EXTENSION_CONFIDENTIAL => [AttributeType::EXTENSION_ENABLED_VALUE]],
        ));

        $other = (new Schema())->addAttributeType(new AttributeType(
            oid: '2.5.4.35',
            names: ['userPassword'],
            desc: 'from another directory',
        ));
        $userPassword = $this->subject->merge($other)
            ->getAttributeType('userPassword');

        self::assertNotNull($userPassword);
        self::assertTrue($userPassword->isConfidential());
        self::assertSame(
            'from another directory',
            $userPassword->desc,
        );
    }

    public function test_merge_lets_the_incoming_definition_override_an_extension_value(): void
    {
        $this->subject->addAttributeType(new AttributeType(
            oid: '2.5.4.35',
            names: ['userPassword'],
            extensions: [AttributeType::EXTENSION_CONFIDENTIAL => [AttributeType::EXTENSION_ENABLED_VALUE]],
        ));

        $other = (new Schema())->addAttributeType(new AttributeType(
            oid: '2.5.4.35',
            names: ['userPassword'],
            extensions: [AttributeType::EXTENSION_CONFIDENTIAL => ['FALSE']],
        ));
        $merged = $this->subject->merge($other);

        self::assertFalse($merged->getAttributeType('userPassword')?->isConfidential());
    }

    public function test_merge_leaves_a_definition_alone_when_nothing_it_replaces_has_extensions(): void
    {
        $this->subject->addAttributeType($this->cn);

        $override = new AttributeType(
            oid: '2.5.4.3',
            names: ['cn'],
            extensions: ['X-ORIGIN' => ['RFC 4519']],
        );
        $merged = $this->subject->merge((new Schema())->addAttributeType($override));

        self::assertSame(
            $override,
            $merged->getAttributeType('cn'),
        );
    }

    public function test_fluent_add_methods_return_same_instance(): void
    {
        $schema = new Schema();

        self::assertSame(
            $schema,
            $schema->addAttributeType($this->cn),
        );
        self::assertSame(
            $schema,
            $schema->addObjectClass($this->person),
        );
        self::assertSame(
            $schema,
            $schema->addMatchingRule($this->caseIgnore),
        );
        self::assertSame(
            $schema,
            $schema->addSyntax($this->dirString),
        );
    }

    public function test_is_integer_ordered_is_null_for_an_unknown_attribute(): void
    {
        self::assertNull($this->subject->isIntegerOrdered('doesNotExist'));
    }

    public function test_is_integer_ordered_is_true_for_an_explicit_integer_ordering_rule(): void
    {
        $this->subject->addAttributeType(new AttributeType(
            oid: '1.2.3.4',
            names: ['explicitInt'],
            orderingOid: MatchingRuleOid::OID_INTEGER_ORDERING_MATCH,
            syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
        ));

        self::assertTrue($this->subject->isIntegerOrdered('explicitInt'));
    }

    public function test_is_integer_ordered_is_inferred_from_integer_syntax_without_an_ordering_rule(): void
    {
        $this->subject->addAttributeType(new AttributeType(
            oid: '1.2.3.5',
            names: ['syntaxInt'],
            syntaxOid: SyntaxOid::OID_INTEGER,
        ));

        self::assertTrue($this->subject->isIntegerOrdered('syntaxInt'));
    }

    public function test_is_integer_ordered_lets_an_explicit_ordering_rule_win_over_the_syntax(): void
    {
        $this->subject->addAttributeType(new AttributeType(
            oid: '1.2.3.6',
            names: ['stringOrdered'],
            orderingOid: MatchingRuleOid::OID_CASE_IGNORE_ORDERING_MATCH,
            syntaxOid: SyntaxOid::OID_INTEGER,
        ));

        self::assertFalse($this->subject->isIntegerOrdered('stringOrdered'));
    }
}
