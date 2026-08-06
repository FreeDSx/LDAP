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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl\Subject;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\SubjectEvaluationException;
use FreeDSx\Ldap\Server\AccessControl\Subject\CallbackSubjectMatcher;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class CallbackSubjectMatcherTest extends TestCase
{
    public function test_it_should_delegate_to_callback_returning_true(): void
    {
        $subject = new CallbackSubjectMatcher(
            fn(TokenInterface $token, Dn $dn): bool => true,
        );

        self::assertTrue($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            new Dn('dc=foo,dc=bar'),
        ));
    }

    public function test_it_should_delegate_to_callback_returning_false(): void
    {
        $subject = new CallbackSubjectMatcher(
            fn(TokenInterface $token, Dn $dn): bool => false,
        );

        self::assertFalse($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            new Dn('dc=foo,dc=bar'),
        ));
    }

    public function test_it_should_pass_token_and_dn_to_callback(): void
    {
        $capturedToken = null;
        $capturedDn = null;

        $token = BindToken::fromDn(
            'cn=admin,dc=foo,dc=bar',
        );
        $dn = new Dn('dc=foo,dc=bar');

        $subject = new CallbackSubjectMatcher(
            function (TokenInterface $t, Dn $d) use (&$capturedToken, &$capturedDn): bool {
                $capturedToken = $t;
                $capturedDn = $d;

                return true;
            },
        );

        $subject->matches(
            $token,
            $dn,
        );

        self::assertSame(
            $token,
            $capturedToken,
        );
        self::assertSame(
            $dn,
            $capturedDn,
        );
    }

    public function test_it_should_report_it_cannot_decide_when_the_callback_throws(): void
    {
        $subject = new CallbackSubjectMatcher(
            fn(TokenInterface $token, Dn $dn): bool => throw new RuntimeException('oh no!'),
        );

        $this->expectException(SubjectEvaluationException::class);

        $subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            new Dn('dc=foo,dc=bar'),
        );
    }
}
