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
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\AnySubjectMatcher;
use FreeDSx\Ldap\Server\AccessControl\Subject\CallbackSubjectMatcher;
use FreeDSx\Ldap\Server\AccessControl\Subject\SelfSubjectMatcher;
use PHPUnit\Framework\TestCase;

final class ConfidentialAccessRuleTest extends TestCase
{
    public function test_a_self_subject_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        ConfidentialAccessRule::allow(
            new SelfSubjectMatcher(),
            'userPassword',
        );
    }

    public function test_a_callback_subject_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        ConfidentialAccessRule::deny(
            new CallbackSubjectMatcher(static fn(): bool => true),
            'userPassword',
        );
    }

    public function test_a_subject_needing_no_target_is_accepted(): void
    {
        $rule = ConfidentialAccessRule::allowAny(new AnySubjectMatcher());

        self::assertSame(
            [],
            $rule->attributes,
        );
    }
}
