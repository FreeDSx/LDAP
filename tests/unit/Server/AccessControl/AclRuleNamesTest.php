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

use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\AccessControl\AclRuleNames;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\FilterAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\AnySubjectMatcher;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use PHPUnit\Framework\TestCase;

final class AclRuleNamesTest extends TestCase
{
    private AclRuleNames $subject;

    private AclRules $rules;

    protected function setUp(): void
    {
        $this->subject = new AclRuleNames(SchemaResource::Core->load());
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
}
