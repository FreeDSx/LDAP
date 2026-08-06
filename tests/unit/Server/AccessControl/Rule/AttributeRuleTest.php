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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl\Rule;

use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Subject\AnySubjectMatcher;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use PHPUnit\Framework\TestCase;

final class AttributeRuleTest extends TestCase
{
    public function test_allow_sets_effect_to_allow(): void
    {
        $rule = AttributeRule::allow(new AnySubjectMatcher());

        self::assertSame(
            Effect::Allow,
            $rule->effect,
        );
    }

    public function test_deny_sets_effect_to_deny(): void
    {
        $rule = AttributeRule::deny(new AnySubjectMatcher());

        self::assertSame(
            Effect::Deny,
            $rule->effect,
        );
    }

    public function test_empty_attributes_list_when_none_specified(): void
    {
        $rule = AttributeRule::deny(new AnySubjectMatcher());

        self::assertSame(
            [],
            $rule->attributes,
        );
    }

    public function test_attribute_names_are_stored_lowercase(): void
    {
        $rule = AttributeRule::deny(
            new AnySubjectMatcher(),
            new AnyTargetMatcher(),
            'userPassword',
            'CN',
        );

        self::assertSame(
            ['userpassword', 'cn'],
            $rule->attributes,
        );
    }

    public function test_attribute_names_from_the_constructor_are_normalized(): void
    {
        $rule = new AttributeRule(
            Effect::Deny,
            new AnySubjectMatcher(),
            new AnyTargetMatcher(),
            ['userPassword', 'CN;binary'],
        );

        self::assertSame(
            ['userpassword', 'cn'],
            $rule->attributes,
        );
    }

    public function test_default_target_is_any_target_matcher(): void
    {
        $rule = AttributeRule::deny(new AnySubjectMatcher());

        self::assertInstanceOf(
            AnyTargetMatcher::class,
            $rule->target,
        );
    }
}
