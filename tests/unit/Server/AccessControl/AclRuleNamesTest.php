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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl;

use Closure;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Schema\AttributeTypeSpelling;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\AccessControl\AclRuleNames;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\ExtendedOperationRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\FilterAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\RelocationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\AnySubjectMatcher;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use WeakReference;

final class AclRuleNamesTest extends TestCase
{
    private AclRuleNames $subject;

    private AclRules $rules;

    protected function setUp(): void
    {
        $schema = SchemaResource::Core->load();
        $this->subject = new AclRuleNames(
            $schema,
            new AttributeTypeSpelling($schema),
        );
        $this->rules = AclRules::fromEmpty(
            operations: [
                OperationRule::allow(new AnySubjectMatcher()),
            ],
            attributes: [
                AttributeRule::deny(
                    new AnySubjectMatcher(),
                    new AnyTargetMatcher(),
                    'commonName',
                    'shoeSize',
                )->forRead(),
            ],
            confidential: [
                ConfidentialAccessRule::allow(
                    new AnySubjectMatcher(),
                    '2.5.4.35',
                ),
            ],
            filters: [
                FilterAccessRule::deny(
                    new AnySubjectMatcher(),
                    'surname',
                    'TelephoneNumber',
                ),
            ],
        );
    }

    public function test_attribute_rule_names_are_spelled_by_their_primary_name(): void
    {
        $rule = $this->subject->canonicalize($this->rules)->attributes[0];

        self::assertSame(
            ['cn', 'shoesize'],
            $rule->attributes,
        );
    }

    public function test_an_attribute_rule_keeps_its_effect_and_access(): void
    {
        $rule = $this->subject->canonicalize($this->rules)->attributes[0];

        self::assertSame(
            Effect::Deny,
            $rule->effect,
        );
        self::assertSame(
            AttributeAccess::Read,
            $rule->access,
        );
    }

    public function test_confidential_rule_names_are_spelled_by_their_primary_name(): void
    {
        $rule = $this->subject->canonicalize($this->rules)->confidential[0];

        self::assertSame(
            ['userPassword'],
            $rule->attributes,
        );
        self::assertSame(
            Effect::Allow,
            $rule->effect,
        );
    }

    public function test_filter_rule_names_are_spelled_by_their_primary_name_unless_only_case_differs(): void
    {
        $rule = $this->subject->canonicalize($this->rules)->filters[0];

        self::assertSame(
            ['sn', 'TelephoneNumber'],
            $rule->attributes,
        );
        self::assertSame(
            Effect::Deny,
            $rule->effect,
        );
    }

    public function test_rules_naming_no_attributes_are_kept_as_given(): void
    {
        self::assertSame(
            $this->rules->operations,
            $this->subject->canonicalize($this->rules)->operations,
        );
    }

    /**
     * @param Closure(AclRules): (OperationRule|AttributeRule|ControlRule|ExtendedOperationRule|ConfidentialAccessRule|RelocationRule|FilterAccessRule) $rule
     */
    #[DataProvider('subjectRuleProvider')]
    public function test_a_subject_dn_naming_a_type_another_way_is_spelled_by_primary_names(
        AclRules $rules,
        Closure $rule,
    ): void {
        self::assertTrue($rule($this->subject->canonicalize($rules))->subject->matches(
            BindToken::fromDn('cn=user,dc=foo,dc=bar'),
            null,
        ));
    }

    /**
     * @return iterable<string, array{AclRules, Closure}>
     */
    public static function subjectRuleProvider(): iterable
    {
        $user = Subject::dn('commonName=user,dc=foo,dc=bar');

        yield 'an operation rule' => [
            AclRules::fromEmpty(operations: [OperationRule::allow($user)]),
            static fn(AclRules $rules): OperationRule => $rules->operations[0],
        ];
        yield 'an attribute rule' => [
            AclRules::fromEmpty(attributes: [AttributeRule::allow($user)]),
            static fn(AclRules $rules): AttributeRule => $rules->attributes[0],
        ];
        yield 'a control rule' => [
            AclRules::fromEmpty(controls: [ControlRule::allow($user)]),
            static fn(AclRules $rules): ControlRule => $rules->controls[0],
        ];
        yield 'an extended operation rule' => [
            AclRules::fromEmpty(extendedOps: [ExtendedOperationRule::allow(Subject::dn('2.5.4.3=user,dc=foo,dc=bar'))]),
            static fn(AclRules $rules): ExtendedOperationRule => $rules->extendedOps[0],
        ];
        yield 'a confidential rule' => [
            AclRules::fromEmpty(confidential: [ConfidentialAccessRule::allowAny($user)]),
            static fn(AclRules $rules): ConfidentialAccessRule => $rules->confidential[0],
        ];
        yield 'a relocation rule' => [
            AclRules::fromEmpty(relocations: [RelocationRule::allow(Subject::dnSubtree('domainComponent=foo,dc=bar'))]),
            static fn(AclRules $rules): RelocationRule => $rules->relocations[0],
        ];
        yield 'a filter rule' => [
            AclRules::fromEmpty(filters: [FilterAccessRule::allow($user)]),
            static fn(AclRules $rules): FilterAccessRule => $rules->filters[0],
        ];
    }

    /**
     * @param Closure(AclRules): (OperationRule|AttributeRule|ControlRule|RelocationRule) $rule
     */
    #[DataProvider('targetRuleProvider')]
    public function test_a_target_dn_naming_a_type_another_way_is_spelled_by_primary_names(
        AclRules $rules,
        Closure $rule,
    ): void {
        self::assertTrue($rule($this->subject->canonicalize($rules))->target->matches(
            new Dn('cn=entry,ou=people,dc=foo,dc=bar'),
        ));
    }

    /**
     * @return iterable<string, array{AclRules, Closure}>
     */
    public static function targetRuleProvider(): iterable
    {
        $anyone = Subject::anyone();
        $entry = Target::dn('commonName=entry,ou=people,dc=foo,dc=bar');

        yield 'an operation rule' => [
            AclRules::fromEmpty(operations: [OperationRule::allow(
                $anyone,
                $entry,
            )]),
            static fn(AclRules $rules): OperationRule => $rules->operations[0],
        ];
        yield 'an attribute rule' => [
            AclRules::fromEmpty(attributes: [AttributeRule::allow(
                $anyone,
                $entry,
            )]),
            static fn(AclRules $rules): AttributeRule => $rules->attributes[0],
        ];
        yield 'a control rule' => [
            AclRules::fromEmpty(controls: [ControlRule::allow(
                $anyone,
                Target::dn('2.5.4.3=entry,ou=people,dc=foo,dc=bar'),
            )]),
            static fn(AclRules $rules): ControlRule => $rules->controls[0],
        ];
        yield 'a relocation rule' => [
            AclRules::fromEmpty(relocations: [RelocationRule::allow(
                $anyone,
                Target::subtree('organizationalUnitName=people,dc=foo,dc=bar'),
            )]),
            static fn(AclRules $rules): RelocationRule => $rules->relocations[0],
        ];
    }

    public function test_a_subject_named_by_several_rules_is_spelled_to_one_shared_matcher(): void
    {
        $admins = Subject::group('commonName=admins,dc=foo,dc=bar');
        $rules = $this->subject->canonicalize(AclRules::fromEmpty()->withFullAccess($admins));

        self::assertSame(
            $rules->operations[0]->subject,
            $rules->relocations[0]->subject,
        );
        self::assertSame(
            $rules->operations[0]->subject,
            $this->subject->subject($admins),
        );
        self::assertNotSame(
            $admins,
            $rules->operations[0]->subject,
        );
    }

    public function test_a_subject_using_primary_names_is_not_kept_alive_by_its_spelling(): void
    {
        $admins = Subject::group('cn=admins,dc=foo,dc=bar');
        $reference = WeakReference::create($admins);

        $this->subject->subject($admins);
        unset($admins);

        self::assertNull($reference->get());
    }

    public function test_a_rule_whose_dns_use_primary_names_is_kept_as_given(): void
    {
        $rules = AclRules::fromEmpty(operations: [OperationRule::allow(
            Subject::group('cn=admins,dc=foo,dc=bar'),
            Target::subtree('ou=people,dc=foo,dc=bar'),
        )]);

        self::assertSame(
            $rules->operations,
            $this->subject->canonicalize($rules)->operations,
        );
    }
}
