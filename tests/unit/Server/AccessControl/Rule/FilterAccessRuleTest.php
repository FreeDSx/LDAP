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

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\FilterAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\AnySubjectMatcher;
use FreeDSx\Ldap\Server\AccessControl\Subject\CallbackSubjectMatcher;
use FreeDSx\Ldap\Server\AccessControl\Subject\SelfSubjectMatcher;
use PHPUnit\Framework\TestCase;

final class FilterAccessRuleTest extends TestCase
{
    public function test_a_self_subject_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        FilterAccessRule::deny(
            new SelfSubjectMatcher(),
            'telephoneNumber',
        );
    }

    public function test_a_callback_subject_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        FilterAccessRule::allow(
            new CallbackSubjectMatcher(static fn(): bool => true),
            'telephoneNumber',
        );
    }

    public function test_a_subject_needing_no_target_is_accepted(): void
    {
        $rule = FilterAccessRule::deny(
            new AnySubjectMatcher(),
            'telephoneNumber',
        );

        self::assertSame(
            Effect::Deny,
            $rule->effect,
        );
        self::assertSame(
            ['telephoneNumber'],
            $rule->attributes,
        );
    }

    public function test_an_empty_attribute_list_is_kept_for_every_attribute(): void
    {
        $rule = FilterAccessRule::deny(new AnySubjectMatcher());

        self::assertSame(
            [],
            $rule->attributes,
        );
    }
}
